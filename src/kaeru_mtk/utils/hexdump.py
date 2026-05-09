from __future__ import annotations


def hexdump(data: bytes, *, width: int = 16, prefix: str = "  ") -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{prefix}{i:08x}  {hexpart}  |{asciipart}|")
    return "\n".join(lines)
