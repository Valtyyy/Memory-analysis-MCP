// memcore/reader.hpp -- FROZEN API CONTRACT: typed reads and value codecs.
#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "memcore/process.hpp"
#include "memcore/types.hpp"

namespace memcore {

// Signed integer types (I8..I64) -> int64_t; unsigned and Ptr -> uint64_t; F32/F64 -> double.
using ScalarValue = std::variant<std::int64_t, std::uint64_t, double>;

// Reads at most max_len characters (code units) starting at addr, stopping at the first NUL.
// encoding: "utf8" | "utf16" | "ascii" (case-insensitive; utf16 = UTF-16LE). Result is UTF-8
// (ascii bytes >= 0x80 are mapped to U+FFFD). Invalid sequences become U+FFFD. Throws MemoryError
// if the first byte is unreadable; stops silently at an unreadable boundary afterwards.
std::string read_string(const Process& proc, Address addr, std::size_t max_len,
                        std::string_view encoding);

ScalarValue read_value(const Process& proc, Address addr, ValueType type);
// Contiguous array of `count` values. Throws if the span is unreadable.
std::vector<ScalarValue> read_values(const Process& proc, Address addr, ValueType type,
                                     std::size_t count);

// Little-endian decode of value_size(type, is64) bytes at p.
ScalarValue decode_value(const std::uint8_t* p, ValueType type, bool is64);
// Inverse of decode_value. Converts between alternatives as needed (e.g. a double given for an
// integer type is truncated; an int64 given for F32 is converted). Out-of-range integers wrap.
std::vector<std::uint8_t> encode_value(ScalarValue v, ValueType type, bool is64);

// Pointer chain: addr = base; for each offset in order: addr = read_ptr(addr) + offset
// (read_ptr reads a pointer-sized value, 4 or 8 bytes per proc.is_64bit(); then the signed
// offset is added with wrap-around). Returns the final addr (NOT dereferenced after the last
// offset). Empty offsets -> returns base unchanged.
// Example: base=B, offsets={0x10,0x20} -> a1=[B]+0x10; a2=[a1]+0x20; returns a2.
// Throws MemoryError if any intermediate read fails.
Address read_pointer_chain(const Process& proc, Address base,
                           const std::vector<std::int64_t>& offsets);

}  // namespace memcore
