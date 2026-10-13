from pathlib import Path
import sys


OLD_MARKER = b"/frida-zymbiote-00000000000000000000000000000000"
NEW_MARKER = b"/runtime-worker-00000000000000000000000000000000"


def main(input_path, output_path):
    payload = Path(input_path).read_bytes()
    if len(OLD_MARKER) != len(NEW_MARKER):
        raise ValueError("zymbiote socket markers must have equal length")
    if payload.count(OLD_MARKER) != 1 or NEW_MARKER in payload:
        raise ValueError(f"{input_path}: unexpected zymbiote socket marker")
    Path(output_path).write_bytes(payload.replace(OLD_MARKER, NEW_MARKER))


if __name__ == "__main__":
    main(*sys.argv[1:])
