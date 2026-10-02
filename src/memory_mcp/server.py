"""FastMCP server exposing read-only Windows process memory analysis tools."""

import argparse
import functools
import sys
from typing import Annotated, Any, Callable, Literal

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import Field

from . import formatting as fmt
from .sessions import registry

try:  # the native module only exists on Windows builds
    from . import _memcore
except ImportError as _e:  # pragma: no cover
    _memcore = None
    _IMPORT_ERROR = _e

INSTRUCTIONS = """\
Read-only inspector for Windows process memory (nothing is ever written to a target).
Workflow: list_processes -> attach_process (returns a handle_id like "h1") -> read_memory /
read_value / read_string / read_pointer_chain, or scan (scan_value then scan_next to narrow,
scan_results to page; scan_pattern for AOB signatures; scan_string for text).
Use list_modules / list_regions to find where to look. Addresses are accepted as integers,
hex strings ("0x7ff612340000"), decimal strings, or module expressions ("game.dll+0x1A2B3C").
All addresses in results are hex strings. Call detach_process when done.
"""

mcp = FastMCP("memory-reader", instructions=INSTRUCTIONS)

_RO = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}

ValueType = Literal["i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "f32", "f64", "ptr"]
CompareOp = Literal[
    "exact", "greater", "less", "between", "changed", "unchanged", "increased", "decreased", "unknown"
]
Handle = Annotated[str, Field(description="Process handle id returned by attach_process (e.g. 'h1').")]
Address = Annotated[
    int | str,
    Field(description="Address: integer, hex string '0x...', decimal string, or 'module.dll+0xOFFSET'."),
]
Number = int | float


def _errors(fn: Callable) -> Callable:
    """Convert backend errors into ToolError with a clear message."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if _memcore is None:
            raise ToolError(f"Native module memory_mcp._memcore is unavailable: {_IMPORT_ERROR}")
        try:
            return fn(*args, **kwargs)
        except ToolError:
            raise
        except _memcore.MemoryError as e:
            raise ToolError(f"Memory error: {e}") from e
        except (ValueError, OverflowError, TypeError) as e:
            raise ToolError(str(e)) from e

    return wrapper


def tool(fn: Callable) -> Callable:
    # Sync tools: FastMCP runs them in a worker thread (run_in_thread=True by default),
    # so long native scans do not block the event loop.
    return mcp.tool(annotations=_RO)(_errors(fn))


def _filter_kwargs(
    writable: bool | None = None,
    executable: bool | None = None,
    type: str | None = None,
    module: str | None = None,
) -> dict[str, Any]:
    return {"writable": writable, "executable": executable, "type": type, "module": module}


def _hex_hit(h: Any) -> dict[str, Any]:
    return {"address": fmt.hex_addr(h.address), "previous": h.previous, "current": h.current}


def _scan_preview(session: Any, preview: int) -> dict[str, Any]:
    sc = session.scanner
    count = sc.count()
    hits = sc.results(0, preview) if preview > 0 else []
    return {
        "scan_id": session.scan_id,
        "type": session.type,
        "count": count,
        "results": [_hex_hit(h) for h in hits],
        "truncated": count > len(hits),
    }


# ---------------------------------------------------------------- base tools


@tool
def list_processes(
    name_filter: Annotated[str | None, Field(description="Case-insensitive substring of the process name.")] = None,
    limit: Annotated[int, Field(ge=1, le=5000, description="Maximum entries to return.")] = 200,
) -> dict[str, Any]:
    """List running processes (pid, ppid, threads, name, bitness)."""
    procs = _memcore.list_processes()
    if name_filter:
        nf = name_filter.lower()
        procs = [p for p in procs if nf in p.name.lower()]
    total = len(procs)
    return {
        "total": total,
        "truncated": total > limit,
        "processes": [
            {"pid": p.pid, "ppid": p.ppid, "threads": p.threads, "name": p.name, "is_64bit": p.is_64bit}
            for p in procs[:limit]
        ],
    }


def _proc_summary(handle_id: str, proc: Any) -> dict[str, Any]:
    return {
        "handle_id": handle_id,
        "pid": proc.pid,
        "name": proc.name(),
        "path": proc.path(),
        "is_64bit": proc.is_64bit,
        "is_alive": proc.is_alive(),
    }


@tool
def attach_process(
    pid: Annotated[int | None, Field(description="Process id. Takes precedence over name.")] = None,
    name: Annotated[
        str | None, Field(description="Process name (exact, case-insensitive; falls back to substring if unique).")
    ] = None,
) -> dict[str, Any]:
    """Open a process for read-only access and return a handle_id. Give pid or name."""
    if pid is None and not name:
        raise ValueError("Provide pid or name")
    if pid is None:
        procs = _memcore.list_processes()
        nl = name.lower()
        matches = [p for p in procs if p.name.lower() == nl]
        if not matches:
            matches = [p for p in procs if nl in p.name.lower()]
        if not matches:
            raise ValueError(f"No process matching name {name!r}")
        if len(matches) > 1:
            cands = ", ".join(f"{p.name} (pid {p.pid})" for p in matches[:20])
            raise ValueError(f"Ambiguous name {name!r}: {len(matches)} matches: {cands}. Use pid instead.")
        pid = matches[0].pid
    existing = registry.find_handle(pid)
    if existing is not None:
        try:
            return {**_proc_summary(existing, registry.get_process(existing)), "already_attached": True}
        except ValueError:
            pass  # stale; attach anew
    proc = _memcore.Process(pid)
    hid = registry.add_process(proc)
    return {**_proc_summary(hid, proc), "already_attached": False}


@tool
def detach_process(handle_id: Handle) -> dict[str, Any]:
    """Release a process handle and delete all scans that belong to it."""
    n = registry.detach(handle_id)
    return {"detached": handle_id, "scans_deleted": n}


@tool
def process_info(handle_id: Handle) -> dict[str, Any]:
    """Describe an attached process (pid, name, path, bitness, module count)."""
    proc = registry.get_process(handle_id)
    info = _proc_summary(handle_id, proc)
    info["module_count"] = len(proc.modules())
    return info


@tool
def list_modules(
    handle_id: Handle,
    name_filter: Annotated[str | None, Field(description="Case-insensitive substring of the module name.")] = None,
    limit: Annotated[int, Field(ge=1, le=5000)] = 200,
) -> dict[str, Any]:
    """List loaded modules (DLLs/EXE) with base address and size."""
    proc = registry.get_process(handle_id)
    mods = proc.modules()
    if name_filter:
        nf = name_filter.lower()
        mods = [m for m in mods if nf in m.name.lower()]
    return {
        "total": len(mods),
        "truncated": len(mods) > limit,
        "modules": [
            {"name": m.name, "path": m.path, "base": fmt.hex_addr(m.base), "size": fmt.hex_addr(m.size)}
            for m in mods[:limit]
        ],
    }


@tool
def list_regions(
    handle_id: Handle,
    readable_only: Annotated[bool, Field(description="Only committed, readable regions.")] = True,
    writable: Annotated[bool | None, Field(description="Filter on writable (None = any).")] = None,
    executable: Annotated[bool | None, Field(description="Filter on executable (None = any).")] = None,
    type: Annotated[str | None, Field(description="Region type: 'image', 'mapped' or 'private'.")] = None,
    module: Annotated[str | None, Field(description="Only regions inside this module name.")] = None,
    limit: Annotated[int, Field(ge=1, le=5000)] = 200,
) -> dict[str, Any]:
    """List virtual memory regions with protection, type and owning module."""
    proc = registry.get_process(handle_id)
    regs = proc.regions(readable_only, **_filter_kwargs(writable, executable, type, module))
    return {
        "total": len(regs),
        "truncated": len(regs) > limit,
        "regions": [
            {
                "base": fmt.hex_addr(r.base),
                "size": fmt.hex_addr(r.size),
                "protect": r.protect_str,
                "type": r.type_str,
                "module": r.module,
            }
            for r in regs[:limit]
        ],
    }


@tool
def resolve_address(
    handle_id: Handle,
    expr: Annotated[str, Field(description="Expression like 'game.dll+0x1000', '0x7ff6...' or a decimal number.")],
) -> dict[str, Any]:
    """Resolve an address expression to an absolute address."""
    proc = registry.get_process(handle_id)
    addr = fmt.parse_address(expr, proc)
    return {"address": fmt.hex_addr(addr), "decimal": addr}


@tool
def read_memory(
    handle_id: Handle,
    address: Address,
    size: Annotated[int, Field(ge=1, le=65536, description="Bytes to read (max 65536).")],
    format: Annotated[Literal["hexdump", "hex", "base64"], Field(description="Output encoding.")] = "hexdump",
) -> dict[str, Any]:
    """Read raw bytes. Partial reads are allowed: bytes_read reports how many were readable."""
    proc = registry.get_process(handle_id)
    addr = fmt.parse_address(address, proc)
    data, n = proc.read_partial(addr, size)
    data = data[:n]
    if format == "hexdump":
        body = fmt.hexdump(data, addr)
    elif format == "hex":
        body = fmt.to_hex(data)
    else:
        body = fmt.to_base64(data)
    out: dict[str, Any] = {
        "address": fmt.hex_addr(addr),
        "requested": size,
        "bytes_read": n,
        "format": format,
        "data": body,
    }
    if n < size:
        out["warning"] = "Read was truncated: memory beyond bytes_read is unreadable."
    return out


@tool
def read_value(
    handle_id: Handle,
    address: Address,
    type: Annotated[ValueType, Field(description="Value type.")],
    count: Annotated[int, Field(ge=1, le=1024, description="Number of consecutive values.")] = 1,
) -> dict[str, Any]:
    """Read one or more typed values (ints, floats, pointers) starting at address."""
    proc = registry.get_process(handle_id)
    addr = fmt.parse_address(address, proc)
    if count == 1:
        v = _memcore.read_value(proc, addr, type)
        return {"address": fmt.hex_addr(addr), "type": type, "value": v}
    vals = _memcore.read_values(proc, addr, type, count)
    size = _memcore.value_size(type, proc.is_64bit)
    return {"address": fmt.hex_addr(addr), "type": type, "stride": size, "count": len(vals), "values": list(vals)}


@tool
def read_string(
    handle_id: Handle,
    address: Address,
    max_len: Annotated[int, Field(ge=1, le=4096, description="Maximum characters to read.")] = 256,
    encoding: Annotated[Literal["utf8", "utf16", "ascii"], Field(description="String encoding.")] = "utf8",
) -> dict[str, Any]:
    """Read a NUL-terminated string."""
    proc = registry.get_process(handle_id)
    addr = fmt.parse_address(address, proc)
    s = _memcore.read_string(proc, addr, max_len, encoding)
    return {"address": fmt.hex_addr(addr), "encoding": encoding, "length": len(s), "value": s}


@tool
def read_pointer_chain(
    handle_id: Handle,
    base: Address,
    offsets: Annotated[
        list[int | str], Field(description="Offsets (ints or hex strings). Each step dereferences then adds the offset.")
    ],
    type: Annotated[
        ValueType | None, Field(description="If set, also read a value of this type at the final address.")
    ] = None,
) -> dict[str, Any]:
    """Follow a multi-level pointer chain and return the final address (and optionally its value)."""
    proc = registry.get_process(handle_id)
    start = fmt.parse_address(base, proc)
    offs = fmt.parse_offsets(offsets)
    final = _memcore.read_pointer_chain(proc, start, offs)
    out: dict[str, Any] = {
        "base": fmt.hex_addr(start),
        "offsets": [fmt.hex_addr(o) if o >= 0 else f"-0x{-o:x}" for o in offs],
        "address": fmt.hex_addr(final),
    }
    if type is not None:
        out["type"] = type
        out["value"] = _memcore.read_value(proc, final, type)
    return out


# ---------------------------------------------------------------- scan tools


@tool
def scan_value(
    handle_id: Handle,
    type: Annotated[ValueType, Field(description="Value type to search for.")],
    compare: Annotated[
        CompareOp, Field(description="Comparison. 'unknown' snapshots every value for later narrowing.")
    ] = "exact",
    value: Annotated[Number | None, Field(description="Value to compare against (not needed for 'unknown').")] = None,
    value2: Annotated[Number | None, Field(description="Upper bound for 'between'.")] = None,
    writable_only: Annotated[bool, Field(description="Only scan writable regions (much faster).")] = True,
    module: Annotated[str | None, Field(description="Restrict to a module's regions.")] = None,
    alignment: Annotated[int, Field(ge=0, description="Address alignment; 0 = natural size of the type.")] = 0,
    preview: Annotated[int, Field(ge=0, le=1000, description="Number of hits to include in the response.")] = 50,
) -> dict[str, Any]:
    """Start a value scan (first scan). Narrow it with scan_next. Returns scan_id, count and a preview."""
    proc = registry.get_process(handle_id)
    scanner = _memcore.ValueScanner(proc, type)
    scanner.first_scan(
        compare,
        value,
        value2,
        True,
        **_filter_kwargs(True if writable_only else None, None, None, module),
        alignment=alignment,
    )
    sid = registry.add_scan(scanner, handle_id, type)
    return _scan_preview(registry.get_scan(sid), preview)


@tool
def scan_next(
    scan_id: Annotated[str, Field(description="Scan id returned by scan_value.")],
    compare: Annotated[CompareOp, Field(description="Comparison against current memory / previous values.")],
    value: Annotated[Number | None, Field(description="Value to compare against.")] = None,
    value2: Annotated[Number | None, Field(description="Upper bound for 'between'.")] = None,
    preview: Annotated[int, Field(ge=0, le=1000)] = 50,
) -> dict[str, Any]:
    """Narrow an existing scan (e.g. 'changed', 'increased', 'exact' with a new value)."""
    session = registry.get_scan(scan_id)
    session.scanner.next_scan(compare, value, value2)
    return _scan_preview(session, preview)


@tool
def scan_results(
    scan_id: Annotated[str, Field(description="Scan id returned by scan_value.")],
    offset: Annotated[int, Field(ge=0)] = 0,
    limit: Annotated[int, Field(ge=1, le=1000)] = 100,
) -> dict[str, Any]:
    """Page through the current hits of a scan."""
    session = registry.get_scan(scan_id)
    count = session.scanner.count()
    hits = session.scanner.results(offset, limit)
    return {
        "scan_id": scan_id,
        "type": session.type,
        "count": count,
        "offset": offset,
        "results": [_hex_hit(h) for h in hits],
        "has_more": offset + len(hits) < count,
    }


@tool
def scan_pattern(
    handle_id: Handle,
    pattern: Annotated[str, Field(description="Hex byte pattern with wildcards, e.g. '48 8B ?? 10 E8 ?? ?? ?? ??'.")],
    module: Annotated[str | None, Field(description="Restrict to a module's regions.")] = None,
    executable_only: Annotated[bool, Field(description="Only scan executable regions.")] = False,
    max_results: Annotated[int, Field(ge=1, le=10000)] = 100,
) -> dict[str, Any]:
    """Search memory for a byte pattern (AOB signature) with ?? wildcards."""
    proc = registry.get_process(handle_id)
    hits = _memcore.scan_pattern(
        proc,
        pattern,
        True,
        **_filter_kwargs(None, True if executable_only else None, None, module),
        max_results=max_results,
    )
    return {
        "count": len(hits),
        "truncated": len(hits) >= max_results,
        "addresses": [fmt.hex_addr(a) for a in hits],
    }


@tool
def scan_string(
    handle_id: Handle,
    text: Annotated[str, Field(description="Text to search for.")],
    encoding: Annotated[
        Literal["utf8", "utf16", "ascii"], Field(description="Encoding of the text in memory.")
    ] = "utf8",
    case_sensitive: bool = True,
    module: Annotated[str | None, Field(description="Restrict to a module's regions.")] = None,
    max_results: Annotated[int, Field(ge=1, le=10000)] = 100,
) -> dict[str, Any]:
    """Search memory for a text string."""
    proc = registry.get_process(handle_id)
    hits = _memcore.scan_string(
        proc,
        text,
        encoding,
        case_sensitive,
        True,
        **_filter_kwargs(None, None, None, module),
        max_results=max_results,
    )
    return {
        "count": len(hits),
        "truncated": len(hits) >= max_results,
        "addresses": [fmt.hex_addr(a) for a in hits],
    }


@tool
def list_scans() -> dict[str, Any]:
    """List active value scans."""
    out = []
    for s in registry.list_scans():
        out.append(
            {
                "scan_id": s.scan_id,
                "handle_id": s.handle_id,
                "type": s.type,
                "count": s.scanner.count(),
                "created": s.created,
            }
        )
    return {"scans": out}


@tool
def delete_scan(scan_id: Annotated[str, Field(description="Scan id to delete.")]) -> dict[str, Any]:
    """Free a scan and its stored results."""
    registry.delete_scan(scan_id)
    return {"deleted": scan_id}


# ---------------------------------------------------------------- entry point


def main() -> None:
    parser = argparse.ArgumentParser(prog="memory-mcp", description="Read-only Windows memory MCP server")
    parser.add_argument("--transport", choices=["stdio", "http", "sse"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    if sys.platform != "win32":
        print("memory-mcp only supports Windows (it reads process memory via the Win32 API).", file=sys.stderr)
        sys.exit(1)
    if _memcore is None:
        print(f"Native module memory_mcp._memcore failed to import: {_IMPORT_ERROR}", file=sys.stderr)
        sys.exit(1)

    if args.transport == "stdio":
        mcp.run(show_banner=False)
    else:
        mcp.run(transport=args.transport, host=args.host, port=args.port, show_banner=False)


if __name__ == "__main__":
    main()
