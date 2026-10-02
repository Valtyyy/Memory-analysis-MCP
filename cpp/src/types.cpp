#include "memcore/types.hpp"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <string>

namespace memcore {

namespace {
std::string format_error(const std::string& message, std::uint32_t code)
{
    if (code == 0) return message;
    char* buf = nullptr;
    DWORD n = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, 0, reinterpret_cast<LPSTR>(&buf), 0, nullptr);
    std::string text;
    if (n && buf) {
        text.assign(buf, n);
        while (!text.empty() && (text.back() == '\r' || text.back() == '\n' || text.back() == ' '))
            text.pop_back();
    }
    if (buf) LocalFree(buf);
    std::string out = message + ": ";
    if (!text.empty()) out += text + " ";
    out += "(error " + std::to_string(code) + ")";
    return out;
}
}  // namespace

MemoryError::MemoryError(const std::string& message, std::uint32_t win32_error)
    : std::runtime_error(format_error(message, win32_error)), win32_error_(win32_error)
{
}

std::size_t value_size(ValueType t, bool is_64bit_target)
{
    switch (t) {
        case ValueType::I8:
        case ValueType::U8:
            return 1;
        case ValueType::I16:
        case ValueType::U16:
            return 2;
        case ValueType::I32:
        case ValueType::U32:
        case ValueType::F32:
            return 4;
        case ValueType::I64:
        case ValueType::U64:
        case ValueType::F64:
            return 8;
        case ValueType::Ptr:
            return is_64bit_target ? 8 : 4;
    }
    throw MemoryError("invalid value type");
}

ValueType parse_value_type(std::string_view s)
{
    std::string k(s);
    std::ranges::transform(k, k.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    struct E {
        const char* n;
        ValueType t;
    };
    static const E table[] = {
        {"i8", ValueType::I8},      {"int8", ValueType::I8},    {"sbyte", ValueType::I8},
        {"u8", ValueType::U8},      {"uint8", ValueType::U8},   {"byte", ValueType::U8},
        {"i16", ValueType::I16},    {"int16", ValueType::I16},  {"short", ValueType::I16},
        {"u16", ValueType::U16},    {"uint16", ValueType::U16}, {"ushort", ValueType::U16},
        {"i32", ValueType::I32},    {"int32", ValueType::I32},  {"int", ValueType::I32},
        {"u32", ValueType::U32},    {"uint32", ValueType::U32}, {"uint", ValueType::U32},
        {"i64", ValueType::I64},    {"int64", ValueType::I64},  {"long", ValueType::I64},
        {"u64", ValueType::U64},    {"uint64", ValueType::U64}, {"ulong", ValueType::U64},
        {"f32", ValueType::F32},    {"float", ValueType::F32},  {"f64", ValueType::F64},
        {"double", ValueType::F64}, {"ptr", ValueType::Ptr},    {"pointer", ValueType::Ptr},
    };
    for (const auto& e : table)
        if (k == e.n) return e.t;
    throw MemoryError("unknown value type: " + std::string(s));
}

std::string value_type_name(ValueType t)
{
    switch (t) {
        case ValueType::I8:
            return "i8";
        case ValueType::U8:
            return "u8";
        case ValueType::I16:
            return "i16";
        case ValueType::U16:
            return "u16";
        case ValueType::I32:
            return "i32";
        case ValueType::U32:
            return "u32";
        case ValueType::I64:
            return "i64";
        case ValueType::U64:
            return "u64";
        case ValueType::F32:
            return "f32";
        case ValueType::F64:
            return "f64";
        case ValueType::Ptr:
            return "ptr";
    }
    return "?";
}

}  // namespace memcore
