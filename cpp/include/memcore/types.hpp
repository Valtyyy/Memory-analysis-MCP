// memcore/types.hpp -- FROZEN API CONTRACT: shared basic types.
// All strings in the API are UTF-8 std::string. Headers never include <windows.h>.
#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace memcore {

using Address = std::uint64_t;

enum class ValueType { I8, U8, I16, U16, I32, U32, I64, U64, F32, F64, Ptr };

// Size in bytes of one value. Ptr is 8 if is_64bit_target else 4.
std::size_t value_size(ValueType t, bool is_64bit_target);

// Case-insensitive. Accepted names:
//   "i8","int8","sbyte"; "u8","uint8","byte"; "i16","int16","short"; "u16","uint16","ushort";
//   "i32","int32","int"; "u32","uint32","uint"; "i64","int64","long"; "u64","uint64","ulong";
//   "f32","float"; "f64","double"; "ptr","pointer".
// Throws MemoryError on unknown names.
ValueType parse_value_type(std::string_view s);

// Canonical lowercase name: "i8","u8",...,"f32","f64","ptr".
std::string value_type_name(ValueType t);

struct ProcessInfo {
    std::uint32_t pid = 0;
    std::uint32_t ppid = 0;
    std::uint32_t threads = 0;
    std::string name;  // executable file name, e.g. "notepad.exe"
    bool is_64bit =
        false;  // false if the process is WOW64 (32-bit) or could not be queried on a 64-bit OS
};

struct ModuleInfo {
    std::string name;  // e.g. "kernel32.dll"
    std::string path;  // full path
    Address base = 0;
    std::uint64_t size = 0;
};

struct RegionInfo {
    Address base = 0;
    std::uint64_t size = 0;
    std::uint32_t state = 0;    // MEM_COMMIT / MEM_RESERVE / MEM_FREE raw value
    std::uint32_t protect = 0;  // PAGE_* raw value
    std::uint32_t type = 0;     // MEM_IMAGE / MEM_MAPPED / MEM_PRIVATE raw value
    // Three chars R/W/X ('-' for absent; copy-on-write counts as W) followed by 'G' if
    // PAGE_GUARD is set: "R--","RW-","R-X","RWX","RW-G","---".
    std::string protect_str;
    std::string type_str;  // "image" | "private" | "mapped"
    std::string module;    // owning module name if type is image, else empty
};

struct RegionFilter {
    bool readable_only = true;          // only committed, readable, non-guard, non-noaccess regions
    std::optional<bool> writable;       // if set, must match
    std::optional<bool> executable;     // if set, must match
    std::optional<std::string> type;    // "image" | "private" | "mapped" (case-insensitive)
    std::optional<std::string> module;  // module name (case-insensitive); restrict to its range
    Address start = 0;                  // inclusive
    Address end = UINT64_MAX;           // exclusive upper bound of the address window
};

class MemoryError : public std::runtime_error {
   public:
    // what() == message, or "message: <FormatMessage text> (error N)" when win32_error != 0.
    // The formatting is done in the constructor (implemented in types.cpp).
    explicit MemoryError(const std::string& message, std::uint32_t win32_error = 0);
    std::uint32_t win32_error() const noexcept { return win32_error_; }

   private:
    std::uint32_t win32_error_;
};

}  // namespace memcore
