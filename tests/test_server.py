"""In-memory MCP client tests against the real C++ core (target = this very process)."""

import ctypes
import os
import struct

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from memory_mcp.server import mcp

EXPECTED_TOOLS = {
    "list_processes", "attach_process", "detach_process", "process_info", "list_modules",
    "list_regions", "resolve_address", "read_memory", "read_value", "read_string",
    "read_pointer_chain", "scan_value", "scan_next", "scan_results", "scan_pattern",
    "scan_string", "list_scans", "delete_scan",
}


@pytest.fixture
async def client():
    async with Client(mcp) as c:
        yield c


@pytest.fixture
async def handle(client):
    r = await client.call_tool("attach_process", {"pid": os.getpid()})
    hid = r.data["handle_id"]
    yield hid
    try:
        await client.call_tool("detach_process", {"handle_id": hid})
    except ToolError:
        pass


async def test_tools_listed(client):
    tools = await client.list_tools()
    names = {t.name for t in tools}
    assert EXPECTED_TOOLS <= names
    for t in tools:
        assert t.annotations is not None and t.annotations.read_only_hint is True


async def test_list_processes_contains_self(client):
    r = await client.call_tool("list_processes", {"limit": 5000})
    pids = {p["pid"] for p in r.data["processes"]}
    assert os.getpid() in pids


async def test_attach_and_info(client, handle):
    info = (await client.call_tool("process_info", {"handle_id": handle})).data
    assert info["pid"] == os.getpid()
    assert info["is_alive"] is True
    mods = (await client.call_tool("list_modules", {"handle_id": handle, "name_filter": "python"})).data
    assert mods["total"] >= 1
    assert mods["modules"][0]["base"].startswith("0x")
    regs = (await client.call_tool("list_regions", {"handle_id": handle, "limit": 5})).data
    assert regs["total"] >= 5 and regs["truncated"] is True and len(regs["regions"]) == 5


async def test_read_memory_formats(client, handle):
    buf = ctypes.create_string_buffer(b"HelloMemory\x00\x01\x02", 32)
    addr = ctypes.addressof(buf)
    d = (await client.call_tool("read_memory", {"handle_id": handle, "address": addr, "size": 16})).data
    assert d["bytes_read"] == 16 and d["address"] == hex(addr)
    assert "|HelloMemory" in d["data"]
    h = (await client.call_tool(
        "read_memory", {"handle_id": handle, "address": hex(addr), "size": 5, "format": "hex"})).data
    assert h["data"] == b"Hello".hex()
    b = (await client.call_tool(
        "read_memory", {"handle_id": handle, "address": str(addr), "size": 5, "format": "base64"})).data
    assert b["data"] == "SGVsbG8="


async def test_read_value_and_string(client, handle):
    arr = (ctypes.c_int32 * 4)(10, -20, 30, 40)
    addr = ctypes.addressof(arr)
    v = (await client.call_tool("read_value", {"handle_id": handle, "address": addr, "type": "i32"})).data
    assert v["value"] == 10
    vs = (await client.call_tool(
        "read_value", {"handle_id": handle, "address": addr, "type": "i32", "count": 4})).data
    assert vs["values"] == [10, -20, 30, 40]
    f = ctypes.c_double(3.5)
    fv = (await client.call_tool(
        "read_value", {"handle_id": handle, "address": ctypes.addressof(f), "type": "f64"})).data
    assert fv["value"] == 3.5

    s8 = ctypes.create_string_buffer("héllo".encode("utf-8"))
    r = (await client.call_tool(
        "read_string", {"handle_id": handle, "address": ctypes.addressof(s8)})).data
    assert r["value"] == "héllo"
    s16 = ctypes.create_unicode_buffer("wide text")
    r = (await client.call_tool(
        "read_string",
        {"handle_id": handle, "address": ctypes.addressof(s16), "encoding": "utf16"})).data
    assert r["value"] == "wide text"


async def test_pointer_chain(client, handle):
    target = ctypes.c_int32(1234)
    inner = (ctypes.c_uint64 * 2)(0, ctypes.addressof(target))  # inner[1] -> target
    outer = ctypes.c_uint64(ctypes.addressof(inner))
    r = (await client.call_tool(
        "read_pointer_chain",
        {"handle_id": handle, "base": ctypes.addressof(outer), "offsets": ["0x8", 0], "type": "i32"})).data
    # a1 = [outer] + 8 = &inner[1]; a2 = [a1] + 0 = &target
    assert r["address"] == hex(ctypes.addressof(target))
    assert r["value"] == 1234


async def test_scan_value_flow(client, handle):
    magic = 0x5A5A1234
    var = ctypes.c_int32(magic)
    addr = ctypes.addressof(var)
    r = (await client.call_tool(
        "scan_value", {"handle_id": handle, "type": "i32", "compare": "exact", "value": magic})).data
    sid = r["scan_id"]
    assert r["count"] >= 1
    assert hex(addr) in {h["address"] for h in r["results"]} or r["count"] > len(r["results"])
    var.value = magic + 1
    n = (await client.call_tool(
        "scan_next", {"scan_id": sid, "compare": "exact", "value": magic + 1})).data
    assert n["count"] >= 1
    page = (await client.call_tool("scan_results", {"scan_id": sid, "limit": 1000})).data
    assert hex(addr) in {h["address"] for h in page["results"]}
    scans = (await client.call_tool("list_scans", {})).data
    assert sid in {s["scan_id"] for s in scans["scans"]}
    await client.call_tool("delete_scan", {"scan_id": sid})
    with pytest.raises(ToolError):
        await client.call_tool("scan_results", {"scan_id": sid})


async def test_scan_pattern_and_string(client, handle):
    marker = b"\xde\xad\xbe\xef" + struct.pack("<I", 0x13572468) + b"\xca\xfe"
    buf = ctypes.create_string_buffer(marker, 64)
    addr = ctypes.addressof(buf)
    r = (await client.call_tool(
        "scan_pattern", {"handle_id": handle, "pattern": "DE AD BE EF ?? ?? ?? ?? CA FE",
                         "max_results": 1000})).data
    assert hex(addr) in r["addresses"]

    text = "UniqueNeedle_7f3a9c"
    sbuf = ctypes.create_string_buffer(text.encode(), 64)
    r = (await client.call_tool(
        "scan_string", {"handle_id": handle, "text": text, "max_results": 1000})).data
    assert hex(ctypes.addressof(sbuf)) in r["addresses"]
    r = (await client.call_tool(
        "scan_string", {"handle_id": handle, "text": text.upper(), "case_sensitive": False,
                        "max_results": 1000})).data
    assert hex(ctypes.addressof(sbuf)) in r["addresses"]


async def test_unknown_handle_errors(client):
    with pytest.raises(ToolError, match="Unknown handle_id"):
        await client.call_tool("process_info", {"handle_id": "h999"})
    r = await client.call_tool("read_memory", {"handle_id": "h999", "address": 0, "size": 1},
                               raise_on_error=False)
    assert r.is_error


async def test_bad_address_and_detach(client, handle):
    with pytest.raises(ToolError):
        await client.call_tool("read_memory", {"handle_id": handle, "address": "nonexistent.dll+1", "size": 4})
    d = (await client.call_tool("detach_process", {"handle_id": handle})).data
    assert d["detached"] == handle
    with pytest.raises(ToolError):
        await client.call_tool("process_info", {"handle_id": handle})
