import pytest

from memory_mcp import formatting as fmt


class FakeProcess:
    def __init__(self):
        self.calls = []

    def resolve(self, expr):
        self.calls.append(expr)
        if expr == "game.dll+0x10":
            return 0x7FF600000010
        raise RuntimeError(f"unknown module in {expr!r}")


def test_hex_addr():
    assert fmt.hex_addr(0x7FF612340000) == "0x7ff612340000"
    assert fmt.hex_addr(0) == "0x0"


def test_hexdump_layout():
    data = bytes(range(0x30, 0x30 + 20))
    lines = fmt.hexdump(data, 0x1000).splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("0000000000001000  30 31 32")
    assert lines[0].endswith("|0123456789:;<=>?|")
    assert lines[1].startswith("0000000000001010  40 41 42 43")
    assert lines[1].endswith("|@ABC|")
    # ascii column aligned on short last line
    assert lines[0].index("|") == lines[1].index("|")


def test_hexdump_nonprintable_and_empty():
    assert fmt.hexdump(b"\x00\xffA").endswith("|..A|")
    assert fmt.hexdump(b"") == ""


def test_hex_base64():
    assert fmt.to_hex(b"\x01\xab") == "01ab"
    assert fmt.to_base64(b"hello") == "aGVsbG8="


def test_parse_address_forms():
    p = FakeProcess()
    assert fmt.parse_address(4096, p) == 4096
    assert fmt.parse_address("0x1000", p) == 4096
    assert fmt.parse_address("0X1000", p) == 4096
    assert fmt.parse_address("4096", p) == 4096
    assert fmt.parse_address(" 0x7ff600000000 ", p) == 0x7FF600000000
    assert p.calls == []


def test_parse_address_module_expression():
    p = FakeProcess()
    assert fmt.parse_address("game.dll+0x10", p) == 0x7FF600000010
    assert p.calls == ["game.dll+0x10"]


def test_parse_address_errors():
    p = FakeProcess()
    with pytest.raises(ValueError):
        fmt.parse_address("nope.dll+1", p)
    with pytest.raises(ValueError):
        fmt.parse_address("", p)
    with pytest.raises(ValueError):
        fmt.parse_address(-1, p)
    with pytest.raises(ValueError):
        fmt.parse_address(2**64, p)
    with pytest.raises(ValueError):
        fmt.parse_address(True, p)
    with pytest.raises(ValueError):
        fmt.parse_address(1.5, p)


def test_parse_offsets():
    assert fmt.parse_offsets([0, "0x10", "32", -8, "-0x8"]) == [0, 16, 32, -8, -8]
    with pytest.raises(ValueError):
        fmt.parse_offsets(["zz"])
    with pytest.raises(ValueError):
        fmt.parse_offsets("0x10")
