use core::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub fn make_thread_name(seed: u64) -> [u8; 16] {
    let mut nonce = seed ^ SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut name = [0u8; 16];
    for digit in name[..15].iter_mut().rev() {
        *digit = b"0123456789abcdef"[(nonce & 0xf) as usize];
        nonce >>= 4;
    }
    name
}

#[cfg(test)]
mod tests {
    use super::make_thread_name;

    #[test]
    fn thread_names_are_bounded_and_unique() {
        let first = make_thread_name(0x123456789abcdef);
        let second = make_thread_name(0x123456789abcdef);

        assert_ne!(first, second);
        assert_eq!(first[15], 0);
        assert!(first[..15].iter().all(|c| c.is_ascii_hexdigit()));
        assert!(second[..15].iter().all(|c| c.is_ascii_hexdigit()));
    }
}
