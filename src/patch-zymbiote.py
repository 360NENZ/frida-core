from pathlib import Path
import sys


OLD_MARKER = b"/frida-zymbiote-00000000000000000000000000000000"
NEW_MARKER = b"/runtime-worker-00000000000000000000000000000000"
SYMBOLS = (
    (b"frida_zymbiote_replacement_setargv0", b"relay_zymbiote_replacement_setargv0"),
    (b"frida_zymbiote_replacement_setcontext", b"relay_zymbiote_replacement_setcontext"),
)


def main(input_path, output_path):
    payload = Path(input_path).read_bytes()
    for old, new in ((OLD_MARKER, NEW_MARKER), *SYMBOLS):
        if len(old) != len(new):
            raise ValueError("zymbiote ELF replacements must have equal length")
        if payload.count(old) != 1 or new in payload:
            raise ValueError(f"{input_path}: unexpected zymbiote ELF marker {old!r}")
        payload = payload.replace(old, new)
    Path(output_path).write_bytes(payload)


if __name__ == "__main__":
    main(*sys.argv[1:])
