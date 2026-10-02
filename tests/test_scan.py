"""Scanner tests: run against our own process (read-only scanning of ctypes buffers)."""
import ctypes
import os
import random
import struct
import sys

import pytest

if os.environ.get("MEMCORE_PATH"):
    sys.path.insert(0, os.environ["MEMCORE_PATH"])
    import _memcore as mc
else:
    import memory_mcp._memcore as mc


@pytest.fixture(scope="module")
def proc():
    return mc.Process(os.getpid())


def window(addr, before=0x800, after=0x800):
    return dict(start=max(0, addr - before), end=addr + after)


def hits_of(sc):
    return {h.address: h for h in sc.results(0, max(sc.count(), 1))}


def test_compare_parse():
    assert mc.parse_compare("exact") == mc.CompareOp.Exact
    assert mc.parse_compare("GT") == mc.CompareOp.Greater
    with pytest.raises(mc.MemoryError):
        mc.parse_compare("nope")


def test_i32_exact_changed_increased_decreased(proc):
    val = ctypes.c_int32((0x5A17C0DE ^ random.getrandbits(24)) & 0x7FFFFFFF)
    addr = ctypes.addressof(val)
    sc = mc.ValueScanner(proc, "i32")
    n = sc.first_scan("exact", val.value, writable=True, type="private")
    assert n == sc.count() and n >= 1
    assert addr in hits_of(sc)

    old = val.value
    val.value = old + 5
    sc.next_scan("changed")
    h = hits_of(sc)
    assert addr in h and h[addr].previous == old + 5 and h[addr].current == old + 5
    sc.next_scan("exact", old + 5)
    assert addr in hits_of(sc)

    val.value = old + 10
    sc.next_scan("increased")
    assert addr in hits_of(sc)
    val.value = old + 1
    sc.next_scan("decreased")
    assert addr in hits_of(sc)
    sc.next_scan("unchanged")
    assert addr in hits_of(sc)
    val.value = old + 99
    sc.next_scan("unchanged")
    assert addr not in hits_of(sc)


def test_between_greater_less_signed(proc):
    buf = (ctypes.c_int32 * 4)(-100, -5, 7, 1000)
    addr = ctypes.addressof(buf)
    w = window(addr)
    sc = mc.ValueScanner(proc, "i32")
    sc.first_scan("between", -10, 10, **w)
    h = hits_of(sc)
    assert addr + 4 in h and addr + 8 in h
    assert addr not in h and addr + 12 not in h
    sc2 = mc.ValueScanner(proc, "i32")
    sc2.first_scan("less", -50, **w)
    assert addr in hits_of(sc2) and addr + 4 not in hits_of(sc2)
    sc3 = mc.ValueScanner(proc, "i32")
    sc3.first_scan("greater", 999, **w)
    assert addr + 12 in hits_of(sc3)


def test_unsigned_types_and_alignment(proc):
    buf = (ctypes.c_uint8 * 16)(*([0] * 16))
    addr = ctypes.addressof(buf)
    buf[3] = 200
    buf[8] = 200
    sc = mc.ValueScanner(proc, "u8")
    sc.first_scan("exact", 200, **window(addr, 0, 16))
    assert {addr + 3, addr + 8} <= set(hits_of(sc))
    u64 = ctypes.c_uint64(0xFFFFFFFFFFFFFF00)
    sc = mc.ValueScanner(proc, "u64")
    sc.first_scan("greater", 0xFFFFFFFFFFFFFE00, **window(ctypes.addressof(u64)))
    assert ctypes.addressof(u64) in hits_of(sc)
    b = ctypes.create_string_buffer(16)
    struct.pack_into("<I", b, 1, 0x11223344)
    sc = mc.ValueScanner(proc, "u32")
    sc.first_scan("exact", 0x11223344, alignment=1, **window(ctypes.addressof(b), 0, 16))
    assert ctypes.addressof(b) + 1 in hits_of(sc)
    sc = mc.ValueScanner(proc, "u32")
    sc.first_scan("exact", 0x11223344, alignment=4, **window(ctypes.addressof(b), 0, 16))
    assert ctypes.addressof(b) + 1 not in hits_of(sc)


def test_float_double_tolerance(proc):
    f = ctypes.c_float(123.456)
    d = ctypes.c_double(98765.4321)
    sf = mc.ValueScanner(proc, "f32")
    sf.first_scan("exact", 123.45601, **window(ctypes.addressof(f)))
    assert ctypes.addressof(f) in hits_of(sf)
    sd = mc.ValueScanner(proc, "f64")
    sd.first_scan("exact", 98765.4321 * (1 + 1e-6), **window(ctypes.addressof(d)))
    assert ctypes.addressof(d) in hits_of(sd)
    sd2 = mc.ValueScanner(proc, "f64")
    sd2.first_scan("exact", 98765.4321 * (1 + 1e-3), **window(ctypes.addressof(d)))
    assert ctypes.addressof(d) not in hits_of(sd2)
    d.value = 2.5
    sd.next_scan("changed")
    assert hits_of(sd)[ctypes.addressof(d)].current == 2.5


def test_unknown_then_changed(proc):
    buf = (ctypes.c_int32 * 8)(*range(1000, 1008))
    addr = ctypes.addressof(buf)
    w = window(addr, 0x100, 0x100)
    sc = mc.ValueScanner(proc, "i32")
    n = sc.first_scan("unknown", **w)
    assert n >= 8
    assert len(sc.results(0, 3)) == 3  # paging works on the snapshot too
    buf[5] = 4242
    m = sc.next_scan("changed")
    assert 1 <= m < n
    h = hits_of(sc)
    assert addr + 20 in h and h[addr + 20].previous == 4242
    assert addr + 0 not in h
    buf[5] = 4243
    sc.next_scan("increased")
    assert addr + 20 in hits_of(sc)


def test_unknown_then_exact(proc):
    buf = (ctypes.c_int32 * 4)(11, 22, 33, 44)
    addr = ctypes.addressof(buf)
    sc = mc.ValueScanner(proc, "i32")
    sc.first_scan("unknown", **window(addr, 0x100, 0x100))
    sc.next_scan("exact", 33)
    assert addr + 8 in hits_of(sc)


def test_invalid_ops(proc):
    sc = mc.ValueScanner(proc, "i32")
    with pytest.raises(mc.MemoryError):
        sc.next_scan("exact", 1)  # no first scan
    for op in ("changed", "unchanged", "increased", "decreased"):
        with pytest.raises(mc.MemoryError):
            sc.first_scan(op)
    with pytest.raises(mc.MemoryError):
        sc.first_scan("exact")  # value required
    with pytest.raises(mc.MemoryError):
        sc.first_scan("between", 1)


def test_results_paging(proc):
    buf = (ctypes.c_int32 * 6)(*([777777] * 6))
    addr = ctypes.addressof(buf)
    sc = mc.ValueScanner(proc, "i32")
    sc.first_scan("exact", 777777, **window(addr, 0x40, 0x40))
    n = sc.count()
    assert n >= 6
    a = sc.results(0, 3)
    b = sc.results(3, 3)
    assert len(a) == 3 and len(b) == min(3, n - 3)
    addrs = [h.address for h in a + b]
    assert addrs == sorted(addrs)


def test_scan_pattern_with_wildcards(proc):
    buf = ctypes.create_string_buffer(256)
    marker = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0xC0, 0xFF, 0xEE, 0x42])
    ctypes.memmove(ctypes.addressof(buf) + 77, marker, len(marker))
    addr = ctypes.addressof(buf)
    w = window(addr, 0x100, 0x200)
    assert mc.scan_pattern(proc, "DE AD BE EF 13 37 C0 FF EE 42", **w) == [addr + 77]
    assert mc.scan_pattern(proc, "de ad ?? ef ? 37 c0 ff ee 42", **w) == [addr + 77]
    assert mc.scan_pattern(proc, "DEADBEEF1337??FFEE42", **w) == [addr + 77]
    assert mc.scan_pattern(proc, "DE AD BE EF 13 37 C0 FF EE 43", **w) == []


def test_scan_pattern_across_chunk_boundary(proc):
    size = 9 * 1024 * 1024
    buf = ctypes.create_string_buffer(size)
    base = ctypes.addressof(buf)
    marker = bytes([0xA5, 0x5A, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
    start = (base + 0xFFF) & ~0xFFF
    pos = start + 4 * 1024 * 1024 - 3
    ctypes.memmove(pos, marker, len(marker))
    res = mc.scan_pattern(proc, "A5 5A 11 22 33 44 55 66", start=start, end=start + size - 0x2000)
    assert res == [pos]


def test_scan_pattern_max_results_sorted(proc):
    buf = ctypes.create_string_buffer(512)
    addr = ctypes.addressof(buf)
    for off in (10, 100, 300):
        ctypes.memmove(addr + off, b"\x9C\x8D\x7E\x6F", 4)
    w = window(addr, 0x100, 0x400)
    r = mc.scan_pattern(proc, "9C 8D 7E 6F", max_results=10, **w)
    assert r == [addr + 10, addr + 100, addr + 300]
    assert mc.scan_pattern(proc, "9C 8D 7E 6F", max_results=2, **w) == [addr + 10, addr + 100]


@pytest.mark.parametrize("bad", ["", "   ", "4", "48 8", "ZZ", "48 8G", "4?", "48 ???", "?"])
def test_pattern_parse_errors(proc, bad):
    with pytest.raises(mc.MemoryError):
        mc.scan_pattern(proc, bad)


def test_scan_string_variants(proc):
    s8 = ctypes.create_string_buffer(b"zzQuixoticMarker_UTF8_77zz")
    s16 = ctypes.create_unicode_buffer("zzQuixoticMarker_UTF16_88zz")
    a8, a16 = ctypes.addressof(s8), ctypes.addressof(s16)
    w8, w16 = window(a8, 0x100, 0x200), window(a16, 0x100, 0x200)
    assert mc.scan_string(proc, "QuixoticMarker_UTF8_77", **w8) == [a8 + 2]
    assert mc.scan_string(proc, "quixoticmarker_utf8_77", **w8) == []
    assert mc.scan_string(proc, "quixoticmarker_utf8_77", case_sensitive=False, **w8) == [a8 + 2]
    assert mc.scan_string(proc, "QUIXOTICMARKER_UTF8_77", "ascii", case_sensitive=False, **w8) == [a8 + 2]
    assert mc.scan_string(proc, "QuixoticMarker_UTF16_88", "utf16", **w16) == [a16 + 4]
    assert mc.scan_string(proc, "quixoticMARKER_utf16_88", "utf16", case_sensitive=False, **w16) == [a16 + 4]
    assert mc.scan_string(proc, "quixoticMARKER_utf16_88", "utf16", **w16) == []
    assert mc.scan_string(proc, "QuixoticMarker_UTF16_88", "utf8", **w16) == []


def test_scan_string_errors(proc):
    with pytest.raises(mc.MemoryError):
        mc.scan_string(proc, "")
    with pytest.raises(mc.MemoryError):
        mc.scan_string(proc, "abc", "klingon")
