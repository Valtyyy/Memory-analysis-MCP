# Memory-analysis-MCP

Read-only Windows process memory reader exposed as an MCP server.
C++20 core (WinAPI) → nanobind (`memory_mcp._memcore`) → FastMCP server.

## Install / run

```sh
uv sync                      # builds the C++ extension (VS 2026 / MSVC required)
uv run memory-mcp            # stdio MCP server
uv run memory-mcp --transport http --port 8000
```

Claude Code: `claude mcp add memory-reader -- uv run --directory <repo> memory-mcp` (or use `.mcp.json`).
Reading other users' / elevated processes requires running the server elevated.

## Tools

| Base | Scan |
|---|---|
| `list_processes`, `attach_process`, `detach_process`, `process_info` | `scan_value` (exact/greater/less/between/unknown) |
| `list_modules`, `list_regions`, `resolve_address` | `scan_next` (changed/unchanged/increased/decreased/…) |
| `read_memory` (hexdump/hex/base64), `read_value`, `read_string` | `scan_results`, `list_scans`, `delete_scan` |
| `read_pointer_chain` | `scan_pattern` (AOB, `??` wildcards), `scan_string` (utf8/utf16, case-insensitive) |

Addresses: int, `"0x..."`, or `"module.dll+0x1234"`. Types: `i8 u8 i16 u16 i32 u32 i64 u64 f32 f64 ptr`.
Limits: 50M scan candidates, 512 MiB snapshot for `unknown` first scans.

See `CONTRIBUTING.md` for the build/test workflow.
