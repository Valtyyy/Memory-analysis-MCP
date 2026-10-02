# Memory-analysis-MCP

Read-only Windows process memory reader exposed as an MCP server.
C++20 core (WinAPI) → nanobind (`memory_mcp._memcore`) → FastMCP server.

## Install / run

**Prebuilt wheel** (Windows x64, Python 3.12+): download it from the
[latest release](https://github.com/Valtyyy/Memory-analysis-MCP/releases/latest), then:

```sh
pip install memory_mcp-0.1.0-cp312-abi3-win_amd64.whl
memory-mcp                   # stdio MCP server
```

**From source** (VS 2026 / MSVC required to build the C++ extension):

```sh
uv sync
uv run memory-mcp            # stdio MCP server
uv run memory-mcp --transport http --port 8000
```

Reading other users' / elevated processes requires running the server elevated.

## MCP client configuration

Add the server to `.mcp.json` (project scope) or to the `mcpServers` object of `~/.claude.json` (user scope).
Alternatively: `claude mcp add memory-reader -- memory-mcp`.

Installed from the wheel (`memory-mcp` must be on your `PATH`):

```json
{
  "mcpServers": {
    "memory-reader": {
      "command": "memory-mcp",
      "args": []
    }
  }
}
```

Running from a source checkout (JSON requires escaped backslashes, or use forward slashes):

```json
{
  "mcpServers": {
    "memory-reader": {
      "command": "uv",
      "args": ["run", "--directory", "C:\path\to\Memory-analysis-MCP", "memory-mcp"]
    }
  }
}
```

To read elevated processes, start your MCP client (e.g. Claude Code) from an elevated terminal.

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
