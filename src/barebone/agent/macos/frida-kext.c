
#include <libkern/libkern.h>
#include <mach/kmod.h>
#include <mach/mach_types.h>
#include <miscfs/devfs/devfs.h>
#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/ioccom.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/random.h>
#include <sys/uio.h>
#include <kern/locks.h>
#include <kern/thread.h>
#include <ptrauth.h>

extern int meshlink_agent_start (uint64_t own_base, uint64_t own_size);
extern void meshlink_agent_stop (void);
extern void meshlink_agent_wake (void);

#define MESHLINK_KERNEL_ADDRS(X) \
  X (panic) \
  X (kalloc) X (kfree) X (kalloc_data) X (kfree_data) \
  X (proc_iterate) X (proc_find) X (proc_rele) X (proc_pid) X (proc_best_name) X (proc_task) \
  X (current_task) X (current_thread) X (get_task_map) X (get_bsdtask_info) \
  X (mach_vm_allocate) X (mach_vm_deallocate) X (mach_vm_protect) X (mach_vm_remap) \
  X (kernel_map) X (kernel_pmap) X (pmap_find_phys) X (ml_static_ptovirt) \
  X (mach_vm_region) X (mach_vm_region_recurse) \
  X (vm_map_copyin) X (vm_map_copyout) X (vm_map_wire_external) \
  X (thread_create) X (thread_set_state) X (thread_resume) X (thread_suspend) \
  X (thread_terminate) X (kernel_thread_start) \
  X (task_suspend) X (task_resume) X (task_clear_return_wait) X (task_threads) X (task_info) \
  X (task_restartable_ranges_register) \
  X (assert_wait) X (assert_wait_timeout) X (thread_block) X (thread_wakeup) \
  X (thread_wakeup_prim) X (wakeup) X (ulock_wake) \
  X (mach_absolute_time) X (absolutetime_to_nanoseconds) X (clock_get_calendar_microtime) \
  X (ml_io_map) X (ml_vtophys) X (ml_static_vtop) \
  X (copyin) X (copyout) X (sysent) X (IOLog) \
  X (convert_port_to_thread) X (convert_port_to_thread_read) \
  X (convert_port_to_thread_inspect) \
  X (sock_socket) X (sock_connect) X (sock_send) X (sock_receive) X (sock_close)

#define MESHLINK_DEFINE_SLOT(name) void * _##name;
MESHLINK_KERNEL_ADDRS (MESHLINK_DEFINE_SLOT)
#undef MESHLINK_DEFINE_SLOT

typedef struct _MeshlinkKernelAddr MeshlinkKernelAddr;

struct _MeshlinkKernelAddr
{
  const char * name;
  void ** slot;
};

static const MeshlinkKernelAddr meshlink_kernel_addrs[] = {
#define MESHLINK_LIST_SLOT(name) { #name, &_##name },
  MESHLINK_KERNEL_ADDRS (MESHLINK_LIST_SLOT)
#undef MESHLINK_LIST_SLOT
};

extern void * meshlink_kext_init_start __asm ("section$start$__DATA$__mod_init_func");
extern void * meshlink_kext_init_end __asm ("section$end$__DATA$__mod_init_func");

const uintptr_t meshlink_agent_init_start = (uintptr_t) &meshlink_kext_init_start;
const uintptr_t meshlink_agent_init_end = (uintptr_t) &meshlink_kext_init_end;

const uintptr_t meshlink_agent_private_start = 0;
const uintptr_t meshlink_agent_heap_start = 0;
const uintptr_t meshlink_agent_relocs_start = 0;
const uintptr_t meshlink_agent_relocs_end = 0;

typedef int (* FridaProcCallout) (proc_t process, void * argument);

const unsigned meshlink_agent_disc_thread_continue =
    ptrauth_type_discriminator (thread_continue_t);
const unsigned meshlink_agent_disc_proc_callout =
    ptrauth_type_discriminator (FridaProcCallout);

_Static_assert (ptrauth_type_discriminator (thread_continue_t) == 0xd507,
    "the agent signs a thread's entry with 0xd507");

int
getentropy (void * buffer, size_t size)
{
  read_random (buffer, (u_int) size);

  return 0;
}

void
sys_icache_invalidate (void * start, size_t size)
{
  flush_dcache ((vm_offset_t) start, (unsigned) size, FALSE);
  invalidate_icache ((vm_offset_t) start, (unsigned) size, FALSE);
}

#define MESHLINK_IOC_SET_ADDR _IOW ('M', 1, MeshlinkAddrRequest)
#define MESHLINK_IOC_START _IO ('M', 2)
#define MESHLINK_IOC_GET_IMAGE _IOR ('M', 3, MeshlinkImageInfo)

typedef struct _MeshlinkAddrRequest MeshlinkAddrRequest;
typedef struct _MeshlinkImageInfo MeshlinkImageInfo;

struct _MeshlinkAddrRequest
{
  char name[64];
  uint64_t address;
};

struct _MeshlinkImageInfo
{
  uint64_t base;
  uint64_t size;
};

#define MESHLINK_LINK_ROOM (1024 * 1024)

typedef struct _MeshlinkLink MeshlinkLink;

struct _MeshlinkLink
{
  lck_mtx_t * lock;
  bool open;

  uint8_t * to_host;
  size_t to_host_len;

  uint8_t * from_host;
  size_t from_host_len;
};

static MeshlinkLink meshlink_link;
static lck_grp_t * meshlink_lock_group;

static int meshlink_dev_open (dev_t dev, int flags, int devtype, struct proc * p);
static int meshlink_dev_close (dev_t dev, int flags, int devtype, struct proc * p);
static int meshlink_dev_read (dev_t dev, struct uio * uio, int ioflag);
static int meshlink_dev_write (dev_t dev, struct uio * uio, int ioflag);
static int meshlink_dev_ioctl (dev_t dev, u_long cmd, caddr_t data, int fflag, struct proc * p);

static struct cdevsw meshlink_cdevsw = {
  .d_open = meshlink_dev_open,
  .d_close = meshlink_dev_close,
  .d_read = meshlink_dev_read,
  .d_write = meshlink_dev_write,
  .d_ioctl = meshlink_dev_ioctl,
  .d_stop = eno_stop,
  .d_reset = eno_reset,
  .d_ttys = NULL,
  .d_select = eno_select,
  .d_mmap = eno_mmap,
  .d_strategy = eno_strat,
  .d_reserved_1 = eno_getc,
  .d_reserved_2 = eno_putc,
  .d_type = 0
};

static int meshlink_major = -1;
static void * meshlink_node = NULL;
static bool meshlink_running = false;
static uint64_t meshlink_own_base = 0;
static uint64_t meshlink_own_size = 0;

kern_return_t
meshlink_kext_start (kmod_info_t * ki, void * d)
{
  meshlink_own_base = ki->address;
  meshlink_own_size = ki->size;

  meshlink_lock_group = lck_grp_alloc_init ("meshlink", LCK_GRP_ATTR_NULL);
  if (meshlink_lock_group == NULL)
    return KERN_FAILURE;
  meshlink_link.lock = lck_mtx_alloc_init (meshlink_lock_group, LCK_ATTR_NULL);

  meshlink_major = cdevsw_add (-1, &meshlink_cdevsw);
  if (meshlink_major == -1)
    return KERN_FAILURE;

  meshlink_node = devfs_make_node (makedev (meshlink_major, 0), DEVFS_CHAR, UID_ROOT, GID_WHEEL, 0600,
      "meshlink");
  if (meshlink_node == NULL)
  {
    cdevsw_remove (meshlink_major, &meshlink_cdevsw);
    meshlink_major = -1;
    return KERN_FAILURE;
  }

  return KERN_SUCCESS;
}

kern_return_t
meshlink_kext_stop (kmod_info_t * ki, void * d)
{
  if (meshlink_running)
  {
    meshlink_agent_stop ();
    meshlink_running = false;
  }

  if (meshlink_node != NULL)
  {
    devfs_remove (meshlink_node);
    meshlink_node = NULL;
  }

  if (meshlink_major != -1)
  {
    cdevsw_remove (meshlink_major, &meshlink_cdevsw);
    meshlink_major = -1;
  }

  return KERN_SUCCESS;
}

KMOD_EXPLICIT_DECL (re.meshlink.agent, "1.0", meshlink_kext_start, meshlink_kext_stop)

static int
meshlink_dev_open (dev_t dev, int flags, int devtype, struct proc * p)
{
  int result = 0;

  lck_mtx_lock (meshlink_link.lock);

  if (meshlink_link.open)
  {
    result = EBUSY;
  }
  else
  {
    meshlink_link.to_host = _MALLOC (MESHLINK_LINK_ROOM, M_TEMP, M_WAITOK);
    meshlink_link.from_host = _MALLOC (MESHLINK_LINK_ROOM, M_TEMP, M_WAITOK);
    if (meshlink_link.to_host != NULL && meshlink_link.from_host != NULL)
    {
      meshlink_link.to_host_len = 0;
      meshlink_link.from_host_len = 0;
      meshlink_link.open = true;
    }
    else
    {
      result = ENOMEM;
    }
  }

  lck_mtx_unlock (meshlink_link.lock);

  return result;
}

static int
meshlink_dev_close (dev_t dev, int flags, int devtype, struct proc * p)
{
  lck_mtx_lock (meshlink_link.lock);

  meshlink_link.open = false;
  if (meshlink_link.to_host != NULL)
  {
    _FREE (meshlink_link.to_host, M_TEMP);
    meshlink_link.to_host = NULL;
  }
  if (meshlink_link.from_host != NULL)
  {
    _FREE (meshlink_link.from_host, M_TEMP);
    meshlink_link.from_host = NULL;
  }

  wakeup (&meshlink_link);

  lck_mtx_unlock (meshlink_link.lock);

  return 0;
}

static int
meshlink_dev_read (dev_t dev, struct uio * uio, int ioflag)
{
  int result = 0;

  lck_mtx_lock (meshlink_link.lock);

  while (meshlink_link.open && meshlink_link.to_host_len == 0)
  {
    if (msleep (&meshlink_link, meshlink_link.lock, PCATCH, "meshlink", NULL) != 0)
    {
      lck_mtx_unlock (meshlink_link.lock);
      return EINTR;
    }
  }

  if (meshlink_link.to_host_len != 0)
  {
    size_t n = MIN ((size_t) uio_resid (uio), meshlink_link.to_host_len);

    result = uiomove ((const char *) meshlink_link.to_host, (int) n, uio);
    if (result == 0)
    {
      memmove (meshlink_link.to_host, meshlink_link.to_host + n, meshlink_link.to_host_len - n);
      meshlink_link.to_host_len -= n;
    }
  }

  lck_mtx_unlock (meshlink_link.lock);

  return result;
}

static int
meshlink_dev_write (dev_t dev, struct uio * uio, int ioflag)
{
  size_t n;
  int result;

  lck_mtx_lock (meshlink_link.lock);

  n = MIN ((size_t) uio_resid (uio), MESHLINK_LINK_ROOM - meshlink_link.from_host_len);
  if (n == 0)
  {
    lck_mtx_unlock (meshlink_link.lock);
    return ENOBUFS;
  }

  result = uiomove ((char *) meshlink_link.from_host + meshlink_link.from_host_len, (int) n, uio);
  if (result == 0)
    meshlink_link.from_host_len += n;

  lck_mtx_unlock (meshlink_link.lock);

  if (result == 0 && meshlink_running)
    meshlink_agent_wake ();

  return result;
}

int
meshlink_kmod_link_open (void)
{
  return meshlink_link.open ? 0 : -1;
}

void
meshlink_kmod_link_close (void)
{
}

int
meshlink_kmod_link_send (const void * data, size_t size)
{
  lck_mtx_lock (meshlink_link.lock);

  if (!meshlink_link.open || meshlink_link.to_host_len + size > MESHLINK_LINK_ROOM)
  {
    lck_mtx_unlock (meshlink_link.lock);
    return -1;
  }

  memcpy (meshlink_link.to_host + meshlink_link.to_host_len, data, size);
  meshlink_link.to_host_len += size;

  wakeup (&meshlink_link);

  lck_mtx_unlock (meshlink_link.lock);

  return 0;
}

bool
meshlink_kmod_link_pending (void)
{
  bool pending;

  lck_mtx_lock (meshlink_link.lock);

  pending = meshlink_link.from_host_len != 0;

  lck_mtx_unlock (meshlink_link.lock);

  return pending;
}

ssize_t
meshlink_kmod_link_recv (void * data, size_t size)
{
  size_t n;

  lck_mtx_lock (meshlink_link.lock);

  n = MIN (size, meshlink_link.from_host_len);
  if (n != 0)
  {
    memcpy (data, meshlink_link.from_host, n);
    memmove (meshlink_link.from_host, meshlink_link.from_host + n, meshlink_link.from_host_len - n);
    meshlink_link.from_host_len -= n;
  }

  lck_mtx_unlock (meshlink_link.lock);

  return (ssize_t) n;
}

static int
meshlink_dev_ioctl (dev_t dev, u_long cmd, caddr_t data, int fflag, struct proc * p)
{
  switch (cmd)
  {
    case MESHLINK_IOC_SET_ADDR:
    {
      MeshlinkAddrRequest * r = (MeshlinkAddrRequest *) data;
      size_t i;

      r->name[sizeof (r->name) - 1] = '\0';

      for (i = 0; i != sizeof (meshlink_kernel_addrs) / sizeof (meshlink_kernel_addrs[0]); i++)
      {
        if (strncmp (meshlink_kernel_addrs[i].name, r->name, sizeof (r->name)) == 0)
        {
          *meshlink_kernel_addrs[i].slot = (void *) (uintptr_t) r->address;
          return 0;
        }
      }

      return ENOENT;
    }
    case MESHLINK_IOC_GET_IMAGE:
    {
      MeshlinkImageInfo * info = (MeshlinkImageInfo *) data;

      info->base = meshlink_own_base;
      info->size = meshlink_own_size;

      return 0;
    }
    case MESHLINK_IOC_START:
    {
      if (meshlink_running)
        return EBUSY;

      if (meshlink_agent_start (meshlink_own_base, meshlink_own_size) != 0)
        return ENOMEM;

      meshlink_running = true;

      return 0;
    }
    default:
      return ENOTTY;
  }
}
