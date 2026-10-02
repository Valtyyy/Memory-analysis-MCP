# Building

Requires VS 2026 (MSVC), CMake, uv. scikit-build-core picks the "Visual Studio 18 2026" generator
automatically, so no vcvars/Developer prompt is needed.

- First build / install deps: `uv sync`
- After editing any `.cpp` / `.hpp` / `CMakeLists.txt`: `uv sync --reinstall-package memory-mcp`
  (~20 s). Python files under `src/memory_mcp/` are editable (redirect mode) and need no rebuild.
- Tests: `uv run pytest`

The native module is `memory_mcp._memcore`. The access is strictly read-only (no WriteProcessMemory).

# Linting (C++)

`.clang-format` and `.clang-tidy` live at the repo root; the LLVM bundled with Visual Studio is used
automatically.

- clang-tidy: `powershell scripts/lint.ps1` (add `-Fix` to apply fixes)
- clang-format check: `powershell scripts/lint.ps1 -Format` (add `-Fix` to reformat in place)
