# Runs clang-tidy (or clang-format check with -Format) on the C++ sources.
# Uses the LLVM bundled with Visual Studio unless clang-tidy is already on PATH.
param([switch]$Format, [switch]$Fix)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

function Find-Tool($name) {
  $cmd = Get-Command $name -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $hit = Get-ChildItem "$env:ProgramFiles\Microsoft Visual Studio\*\*\VC\Tools\Llvm\x64\bin\$name.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($hit) { return $hit.FullName }
  throw "$name not found (install LLVM or the VS 'C++ Clang tools' component)"
}

$files = Get-ChildItem cpp -Recurse -Include *.cpp,*.hpp | ForEach-Object FullName

if ($Format) {
  $fmt = Find-Tool 'clang-format'
  if ($Fix) { & $fmt -i @files } else { & $fmt --dry-run --Werror @files }
  exit $LASTEXITCODE
}

$tidy = Find-Tool 'clang-tidy'
$nb = (& uv run python -m nanobind --include_dir).Trim()
$py = (& uv run python -c "import sysconfig;print(sysconfig.get_path('include'))").Trim()
$flags = @('-std=c++20', '--target=x86_64-pc-windows-msvc', '-fms-compatibility', '-fms-extensions',
  '-DWIN32_LEAN_AND_MEMORY', '-DWIN32_LEAN_AND_MEAN', '-DNOMINMAX', '-DUNICODE', '-D_UNICODE',
  '-Icpp/include', "-I$nb", "-I$py")
$cpp = $files | Where-Object { $_ -like '*.cpp' }
$extra = @(); if ($Fix) { $extra += '--fix' }
& $tidy @extra --quiet @cpp -- @flags
exit $LASTEXITCODE
