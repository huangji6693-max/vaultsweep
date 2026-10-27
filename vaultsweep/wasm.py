import re
from pathlib import Path

WASM_MAGIC = b"\x00asm\x01\x00\x00\x00"
_PRINTABLE_ASCII_RE = re.compile(rb"[\x20-\x7e]{12,}")


def is_wasm_binary(data: bytes) -> bool:
    return data.startswith(WASM_MAGIC)


def extract_wasm_strings(file_path: str | Path, min_len: int = 12) -> list[tuple[int, str]]:
    """Extract printable ASCII strings from a compiled WebAssembly (`.wasm`) binary.

    Returns a list of `(synthetic_line_no, extracted_string)` pairs suitable for
    feeding into VaultSweep's line-based rule engine.
    """
    path = Path(file_path)
    try:
        data = path.read_bytes()
    except OSError:
        return []

    if not is_wasm_binary(data):
        return []

    results: list[tuple[int, str]] = []
    for idx, match in enumerate(_PRINTABLE_ASCII_RE.finditer(data), start=1):
        raw = match.group(0)
        if len(raw) < min_len:
            continue
        text = raw.decode("ascii", errors="ignore").strip()
        if text:
            results.append((idx, text))
    return results
