"""Tests for the C++ core (_memcore), attached to our own process."""
import ctypes
import os
import re
import struct
import sys

import pytest

if os.environ.get("MEMCORE_PATH"):
    sys.path.insert(0, os.environ["MEMCORE_PATH"])
    import _memcore as mc  # type: ignore
else:
    import memory_mcp._memcore as mc  # type: ignore

PID = os.getpid()


@pytest.fixture(scope="module")
def proc():
    return mc.Process(PID)


def addr_of(obj):
    return ctypes.addressof(obj)


def test_list_processes_contains_self():
    procs = mc.list_processes()
    mine = [p for p in procs if p.pid == PID]
    assert mine, "own pid missing"
    assert mine[0].name.lower().endswith(".exe")
    assert mine[0].is_64bit == (struct.calcsize("P") == 8)


def test_process_basics(proc):
    assert proc.pid == PID
    assert proc.is_alive()
    assert proc.is_64bit == (struct.calcsize("P") == 8)
    assert proc.name().lower().startswith("python")
    assert proc.path().lower().endswith(".exe")


def test_nonexistent_process():
    with pytest.raises(mc.MemoryError):
        mc.Process(0xFFFFFFF0)


def test_modules(proc):
    mods = proc.modules()
    names = [m.name.lower() for m in mods]
    assert any(re.fullmatch(r"python(3\d*)?\.dll|python[w]?\.exe", n) for n in names), names
    assert "kernel32.dll" in names
    assert mods[0].name.lower().endswith(".exe")
    k = proc.find_module("KERNEL32.DLL")
    assert k is not None and k.base != 0 and k.size > 0
    assert proc.find_module("no_such_module.dll") is None


def test_regions_and_filters(proc):
    regs = proc.regions()
    assert regs
    assert all(r.protect_str[0] == "R" for r in regs)
    bases = [r.base for r in regs]
    assert bases == sorted(bases)

    priv = proc.regions(type="private")
    assert priv and all(r.type_str == "private" for r in priv)
    img = proc.regions(type="IMAGE")
    assert img and all(r.type_str == "image" and r.module for r in img)

    w = proc.regions(writable=True)
    assert w and all(r.protect_str[1] == "W" for r in w)
    x = proc.regions(executable=True)
    assert x and all(r.protect_str[2] == "X" for r in x)

    k = proc.find_module("kernel32.dll")
    kr = proc.regions(module="KERNEL32.dll")
    assert kr
    assert all(k.base <= r.base < k.base + k.size for r in kr)
    assert all(r.module.lower() == "kernel32.dll" for r in kr)

    # window clipping
    buf = ctypes.create_string_buffer(b"window")
    a = addr_of(buf)
    win = proc.regions(start=a, end=a + 4)
    assert len(win) == 1
    assert win[0].base == a and win[0].size == 4

    # unreadable regions are included when readable_only=False
    allr = proc.regions(readable_only=False)
    assert len(allr) >= len(regs)


def test_read_exact(proc):
    buf = ctypes.create_string_buffer(b"MCP_MAGIC_1234")
    a = addr_of(buf)
    assert proc.read(a, 14) == b"MCP_MAGIC_1234"
    assert proc.read(a, 0) == b""


def test_read_partial(proc):
    buf = ctypes.create_string_buffer(b"MCP_MAGIC_1234")
    a = addr_of(buf)
    data, n = proc.read_partial(a, 14)
    assert data == b"MCP_MAGIC_1234" and n == 14

    # Region with an unreadable second page.
    k32 = ctypes.windll.kernel32
    k32.VirtualAlloc.restype = ctypes.c_void_p
    k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
    base = k32.VirtualAlloc(None, 8192, 0x3000, 0x04)  # COMMIT|RESERVE, RW
    assert base
    try:
        ctypes.memset(base, 0x41, 4096)
        old = ctypes.c_ulong()
        k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_void_p]
        assert k32.VirtualProtect(base + 4096, 4096, 0x01, ctypes.byref(old))  # NOACCESS
        data, n = proc.read_partial(base, 8192)
        assert n == 4096
        assert data[:4096] == b"A" * 4096 and data[4096:] == b"\x00" * 4096
        with pytest.raises(mc.MemoryError):
            proc.read(base, 8192)
    finally:
        k32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
        k32.VirtualFree(base, 0, 0x8000)


def test_read_string(proc):
    buf = ctypes.create_string_buffer(b"MCP_MAGIC_1234")
    assert mc.read_string(proc, addr_of(buf), 256, "utf8") == "MCP_MAGIC_1234"
    assert mc.read_string(proc, addr_of(buf), 3, "ascii") == "MCP"
    assert mc.read_string(proc, addr_of(buf), 256, "UTF8") == "MCP_MAGIC_1234"

    ubuf = ctypes.create_unicode_buffer("héllo 世界 \U0001F600")
    assert mc.read_string(proc, addr_of(ubuf), 256, "utf16") == "héllo 世界 \U0001F600"

    u8 = ctypes.create_string_buffer("café".encode("utf-8"))
    assert mc.read_string(proc, addr_of(u8), 64, "utf8") == "café"
    assert mc.read_string(proc, addr_of(u8), 64, "ascii") == "caf��"

    bad = ctypes.create_string_buffer(b"ab\xffcd")
    assert mc.read_string(proc, addr_of(bad), 64, "utf8") == "ab�cd"

    with pytest.raises(mc.MemoryError):
        mc.read_string(proc, 0, 16, "utf8")
    with pytest.raises(mc.MemoryError):
        mc.read_string(proc, addr_of(buf), 16, "ebcdic")


def test_read_string_at_region_end(proc):
    k32 = ctypes.windll.kernel32
    k32.VirtualAlloc.restype = ctypes.c_void_p
    k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
    base = k32.VirtualAlloc(None, 4096, 0x3000, 0x04)
    try:
        ctypes.memset(base + 4096 - 5, 0x42, 5)  # no NUL before end of region
        # Likely followed by free/reserved memory; must not raise.
        s = mc.read_string(proc, base + 4096 - 5, 100, "ascii")
        assert s.startswith("BBBBB")
    finally:
        k32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
        k32.VirtualFree(base, 0, 0x8000)


def test_read_values(proc):
    i32 = ctypes.c_int32(-123456)
    f64 = ctypes.c_double(3.25)
    f32 = ctypes.c_float(1.5)
    p = ctypes.c_void_p(0x1122334455667788)
    u8 = ctypes.c_uint8(200)
    i8 = ctypes.c_int8(-5)
    u64 = ctypes.c_uint64(2**64 - 1)
    assert mc.read_value(proc, addr_of(i32), "i32") == -123456
    assert mc.read_value(proc, addr_of(i32), "u32") == (-123456) & 0xFFFFFFFF
    assert mc.read_value(proc, addr_of(f64), "f64") == 3.25
    assert mc.read_value(proc, addr_of(f32), "float") == 1.5
    assert mc.read_value(proc, addr_of(p), "ptr") == 0x1122334455667788
    assert mc.read_value(proc, addr_of(u8), "u8") == 200
    assert mc.read_value(proc, addr_of(i8), "i8") == -5
    assert mc.read_value(proc, addr_of(u64), "u64") == 2**64 - 1

    arr = (ctypes.c_int32 * 4)(1, -2, 3, -4)
    assert list(mc.read_values(proc, addr_of(arr), "i32", 4)) == [1, -2, 3, -4]
    assert mc.read_values(proc, addr_of(arr), "i32", 0) == []

    with pytest.raises(mc.MemoryError):
        mc.read_value(proc, 0, "i32")
    with pytest.raises(mc.MemoryError):
        mc.read_value(proc, addr_of(i32), "nonsense")


def test_decode_encode():
    assert mc.decode_value(struct.pack("<i", -7), "i32") == -7
    assert mc.decode_value(struct.pack("<I", 7), "u32") == 7
    assert mc.decode_value(struct.pack("<d", 2.5), "f64") == 2.5
    assert mc.decode_value(struct.pack("<f", 0.5), "f32") == 0.5
    assert mc.decode_value(struct.pack("<I", 0xDEADBEEF), "ptr", False) == 0xDEADBEEF
    assert mc.decode_value(struct.pack("<Q", 0xDEADBEEF12345678), "ptr", True) == 0xDEADBEEF12345678

    assert mc.encode_value(-7, "i32") == struct.pack("<i", -7)
    assert mc.encode_value(300, "u8") == b"\x2c"  # wraps
    assert mc.encode_value(-1, "u16") == b"\xff\xff"
    assert mc.encode_value(3.9, "i32") == struct.pack("<i", 3)  # truncated
    assert mc.encode_value(2, "f32") == struct.pack("<f", 2.0)
    assert mc.encode_value(5, "f64") == struct.pack("<d", 5.0)
    assert len(mc.encode_value(1, "ptr", True)) == 8
    assert len(mc.encode_value(1, "ptr", False)) == 4
    assert mc.encode_value(0x1_0000_0001, "ptr", False) == struct.pack("<I", 1)
    for t, v in [("i8", -3), ("u16", 65000), ("i64", -(2**40)), ("u64", 2**63 + 5), ("f64", -1.25)]:
        assert mc.decode_value(mc.encode_value(v, t), t) == v


def test_pointer_chain(proc):
    class Inner(ctypes.Structure):
        _fields_ = [("pad", ctypes.c_uint64), ("val", ctypes.c_int32), ("pad2", ctypes.c_int32)]

    class Outer(ctypes.Structure):
        _fields_ = [("pad", ctypes.c_uint64), ("inner", ctypes.c_void_p)]

    inner = Inner(0, 0x7777, 0)
    outer = Outer(0, ctypes.addressof(inner))
    holder = ctypes.c_void_p(ctypes.addressof(outer))  # holder -> outer

    # a1 = [holder] + 8 -> &outer.inner ; a2 = [a1] + 8 -> &inner.val
    final = mc.read_pointer_chain(proc, addr_of(holder), [8, 8])
    assert final == ctypes.addressof(inner) + 8
    assert mc.read_value(proc, final, "i32") == 0x7777

    assert mc.read_pointer_chain(proc, addr_of(holder), []) == addr_of(holder)
    # negative offset
    assert mc.read_pointer_chain(proc, addr_of(holder), [-8]) == ctypes.addressof(outer) - 8
    with pytest.raises(mc.MemoryError):
        mc.read_pointer_chain(proc, 0, [0])


def test_resolve(proc):
    mods = proc.modules()
    dll = next(m for m in mods if re.fullmatch(r"python3\d*\.dll", m.name.lower()))
    base = dll.base
    assert proc.resolve(dll.name) == base
    assert proc.resolve(dll.name.upper()) == base
    assert proc.resolve(dll.name + "+0x10") == base + 0x10
    assert proc.resolve(f"  {dll.name}  +  0x10 ") == base + 0x10
    assert proc.resolve(dll.name + "+16") == base + 16
    assert proc.resolve(dll.name + "-0x10") == base - 0x10
    assert proc.resolve("0x1234") == 0x1234
    assert proc.resolve("0XABCdef") == 0xABCDEF
    assert proc.resolve("1234") == 1234
    assert proc.resolve("  0x10 ") == 0x10
    with pytest.raises(mc.MemoryError):
        proc.resolve("nosuchmodule.dll+0x10")
    with pytest.raises(mc.MemoryError):
        proc.resolve("")
    with pytest.raises(mc.MemoryError):
        proc.resolve(dll.name + "+zz")


def test_read_address_zero_raises(proc):
    with pytest.raises(mc.MemoryError):
        proc.read(0, 4)
    with pytest.raises(mc.MemoryError):
        proc.read(0x10, 1)
    data, n = proc.read_partial(0, 16)
    assert n == 0 and data == b"\x00" * 16
