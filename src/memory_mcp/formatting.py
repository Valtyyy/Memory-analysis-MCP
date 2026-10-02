"""Pure-Python helpers: address parsing and byte/hex formatting."""

from __future__ import annotations

import base64
from typing import Any, Iterable

MAX_ADDRESS = 2**64 - 1


def hex_addr(value: int) -> str:
    """Format an integer address/size as ``0x...`` (lowercase)."""
    return f"0x{int(value):x}"


def hexdump(data: bytes, base_address: int = 0, width: int = 16) -> str:
    """Classic hexdump: ``<address>  <hex bytes>  |<ascii>|`` per line.

    The leading column is ``base_address + offset`` formatted as hex.
    """
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        # pad so the ASCII column lines up on short final lines
        hexpart = hexpart.ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base_address + off:016x}  {hexpart}  |{ascii_part}|")
    return "\n".join(lines)


def to_hex(data: bytes) -> str:
    return data.hex()


def to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def parse_int(value: Any, what: str = "value") -> int:
    """Parse an int, ``0x..`` hex string or decimal string into an int."""
    if isinstance(value, bool):
        raise ValueError(f"Invalid {what}: {value!r}")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip().replace("_", "")
        neg = s.startswith("-")
        body = s[1:] if neg else s
        try:
            n = int(body, 16) if body.lower().startswith("0x") else int(body, 10)
        except ValueError:
            raise ValueError(f"Invalid {what}: {value!r} (expected int, '0x...' or decimal)") from None
        return -n if neg else n
    raise ValueError(f"Invalid {what}: {value!r}")


def parse_address(value: int | str, process: Any) -> int:
    """Convert an address argument into an int.

    Accepts an int, ``"0x7ff6..."``, a decimal string, or a module expression
    such as ``"game.dll+0x1234"`` (delegated to ``process.resolve``).
    """
    if isinstance(value, bool):
        raise ValueError(f"Invalid address: {value!r}")
    if isinstance(value, int):
        addr = value
    elif isinstance(value, str):
        s = value.strip()
        if not s:
            raise ValueError("Empty address")
        try:
            addr = parse_int(s, "address")
        except ValueError:
            try:
                addr = int(process.resolve(s))
            except ValueError:
                raise
            except Exception as e:  # _memcore.MemoryError and friends
                raise ValueError(f"Cannot resolve address expression {s!r}: {e}") from e
    else:
        raise ValueError(f"Invalid address: {value!r}")
    if not 0 <= addr <= MAX_ADDRESS:
        raise ValueError(f"Address out of 64-bit range: {value!r}")
    return addr


def parse_offsets(offsets: Iterable[int | str]) -> list[int]:
    """Parse a list of offsets given as ints or (hex/decimal, optionally negative) strings."""
    if isinstance(offsets, (str, bytes)) or not hasattr(offsets, "__iter__"):
        raise ValueError("offsets must be a list of ints or hex strings")
    return [parse_int(o, "offset") for o in offsets]
