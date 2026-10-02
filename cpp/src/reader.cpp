// reader.cpp -- typed reads and value codecs.
#include "memcore/reader.hpp"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstring>

namespace memcore {

namespace {

void append_utf8(std::string& s, std::uint32_t cp)
{
    if (cp < 0x80)
        s += static_cast<char>(cp);
    else if (cp < 0x800) {
        s += static_cast<char>(0xC0 | (cp >> 6));
        s += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        s += static_cast<char>(0xE0 | (cp >> 12));
        s += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        s += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
        s += static_cast<char>(0xF0 | (cp >> 18));
        s += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        s += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        s += static_cast<char>(0x80 | (cp & 0x3F));
    }
}

std::string sanitize_utf8(const std::uint8_t* p, std::size_t n)
{
    std::string out;
    out.reserve(n);
    std::size_t i = 0;
    while (i < n) {
        std::uint8_t c = p[i];
        if (c < 0x80) {
            out += static_cast<char>(c);
            ++i;
            continue;
        }
        std::size_t len = 0;
        std::uint32_t cp = 0, min = 0;
        if (c >= 0xC2 && c <= 0xDF) {
            len = 2;
            cp = c & 0x1F;
            min = 0x80;
        } else if (c >= 0xE0 && c <= 0xEF) {
            len = 3;
            cp = c & 0x0F;
            min = 0x800;
        } else if (c >= 0xF0 && c <= 0xF4) {
            len = 4;
            cp = c & 0x07;
            min = 0x10000;
        }
        bool ok = len != 0 && i + len <= n;
        for (std::size_t k = 1; ok && k < len; ++k) {
            if ((p[i + k] & 0xC0) != 0x80)
                ok = false;
            else
                cp = (cp << 6) | (p[i + k] & 0x3F);
        }
        if (ok && (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))) ok = false;
        if (ok) {
            append_utf8(out, cp);
            i += len;
        } else {
            append_utf8(out, 0xFFFD);
            ++i;
        }
    }
    return out;
}

std::string utf16_to_utf8(const std::uint8_t* p, std::size_t units)
{
    std::string out;
    auto u = [&](std::size_t i) {
        return static_cast<std::uint32_t>(p[2 * i] | (p[2 * i + 1] << 8));
    };
    for (std::size_t i = 0; i < units; ++i) {
        std::uint32_t c = u(i);
        if (c >= 0xD800 && c <= 0xDBFF) {
            if (i + 1 < units && u(i + 1) >= 0xDC00 && u(i + 1) <= 0xDFFF) {
                append_utf8(out, 0x10000 + ((c - 0xD800) << 10) + (u(i + 1) - 0xDC00));
                ++i;
            } else
                append_utf8(out, 0xFFFD);
        } else if (c >= 0xDC00 && c <= 0xDFFF)
            append_utf8(out, 0xFFFD);
        else
            append_utf8(out, c);
    }
    return out;
}

template <typename T>
T load(const std::uint8_t* p)
{
    T v;
    std::memcpy(&v, p, sizeof(T));
    return v;
}

double as_double(const ScalarValue& v)
{
    if (auto* a = std::get_if<std::int64_t>(&v)) return static_cast<double>(*a);
    if (auto* b = std::get_if<std::uint64_t>(&v)) return static_cast<double>(*b);
    return std::get<double>(v);
}

// Integer view with wrap-around semantics; doubles are truncated (saturating at 64 bits).
std::uint64_t as_bits(const ScalarValue& v)
{
    if (auto* a = std::get_if<std::int64_t>(&v)) return static_cast<std::uint64_t>(*a);
    if (auto* b = std::get_if<std::uint64_t>(&v)) return *b;
    double d = std::get<double>(v);
    if (std::isnan(d)) return 0;
    if (d >= 9223372036854775808.0) {
        if (d >= 18446744073709551616.0) return UINT64_MAX;
        return static_cast<std::uint64_t>(d);
    }
    if (d <= -9223372036854775808.0) return static_cast<std::uint64_t>(INT64_MIN);
    return static_cast<std::uint64_t>(static_cast<std::int64_t>(d));
}

}  // namespace

std::string read_string(const Process& proc, Address addr, std::size_t max_len,
                        std::string_view encoding)
{
    std::string enc(encoding);
    std::ranges::transform(enc, enc.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::size_t unit = 0;
    if (enc == "utf8" || enc == "utf-8" || enc == "ascii")
        unit = 1;
    else if (enc == "utf16" || enc == "utf-16" || enc == "utf16le")
        unit = 2;
    else
        throw MemoryError("unknown string encoding: " + std::string(encoding));
    if (max_len == 0) return {};

    const std::size_t max_bytes = max_len * unit;
    std::vector<std::uint8_t> buf;
    std::size_t scanned_units = 0;  // units already checked for NUL
    bool found_nul = false;
    while (buf.size() < max_bytes && !found_nul) {
        Address a = addr + buf.size();
        std::size_t chunk = std::min<std::size_t>(max_bytes - buf.size(), 4096 - (a % 4096));
        std::size_t old = buf.size();
        buf.resize(old + chunk);
        SetLastError(0);
        if (!proc.try_read(a, buf.data() + old, chunk)) {
            DWORD err = GetLastError();
            buf.resize(old);
            if (old == 0) throw MemoryError("cannot read string", err);
            break;
        }
        for (; (scanned_units + 1) * unit <= buf.size(); ++scanned_units) {
            bool nul =
                buf[scanned_units * unit] == 0 && (unit == 1 || buf[scanned_units * unit + 1] == 0);
            if (nul) {
                found_nul = true;
                break;
            }
        }
    }
    std::size_t units = found_nul ? scanned_units : std::min(buf.size() / unit, max_len);
    if (enc == "ascii") {
        std::string out;
        for (std::size_t i = 0; i < units; ++i) {
            if (buf[i] >= 0x80)
                append_utf8(out, 0xFFFD);
            else
                out += static_cast<char>(buf[i]);
        }
        return out;
    }
    if (unit == 1) return sanitize_utf8(buf.data(), units);
    return utf16_to_utf8(buf.data(), units);
}

ScalarValue decode_value(const std::uint8_t* p, ValueType type, bool is64)
{
    switch (type) {
        case ValueType::I8:
            return static_cast<std::int64_t>(load<std::int8_t>(p));
        case ValueType::U8:
            return static_cast<std::uint64_t>(load<std::uint8_t>(p));
        case ValueType::I16:
            return static_cast<std::int64_t>(load<std::int16_t>(p));
        case ValueType::U16:
            return static_cast<std::uint64_t>(load<std::uint16_t>(p));
        case ValueType::I32:
            return static_cast<std::int64_t>(load<std::int32_t>(p));
        case ValueType::U32:
            return static_cast<std::uint64_t>(load<std::uint32_t>(p));
        case ValueType::I64:
            return load<std::int64_t>(p);
        case ValueType::U64:
            return load<std::uint64_t>(p);
        case ValueType::F32:
            return static_cast<double>(load<float>(p));
        case ValueType::F64:
            return load<double>(p);
        case ValueType::Ptr:
            return is64 ? load<std::uint64_t>(p)
                        : static_cast<std::uint64_t>(load<std::uint32_t>(p));
    }
    throw MemoryError("invalid value type");
}

std::vector<std::uint8_t> encode_value(ScalarValue v, ValueType type, bool is64)
{
    std::size_t n = value_size(type, is64);
    std::vector<std::uint8_t> out(n);
    if (type == ValueType::F32) {
        auto f = static_cast<float>(as_double(v));
        std::memcpy(out.data(), &f, 4);
    } else if (type == ValueType::F64) {
        double d = as_double(v);
        std::memcpy(out.data(), &d, 8);
    } else {
        std::uint64_t bits = as_bits(v);
        std::memcpy(out.data(), &bits, n);  // little-endian truncation
    }
    return out;
}

ScalarValue read_value(const Process& proc, Address addr, ValueType type)
{
    auto buf = proc.read(addr, value_size(type, proc.is_64bit()));
    return decode_value(buf.data(), type, proc.is_64bit());
}

std::vector<ScalarValue> read_values(const Process& proc, Address addr, ValueType type,
                                     std::size_t count)
{
    std::size_t sz = value_size(type, proc.is_64bit());
    std::vector<ScalarValue> out;
    if (count == 0) return out;
    auto buf = proc.read(addr, sz * count);
    out.reserve(count);
    for (std::size_t i = 0; i < count; ++i)
        out.push_back(decode_value(buf.data() + i * sz, type, proc.is_64bit()));
    return out;
}

Address read_pointer_chain(const Process& proc, Address base,
                           const std::vector<std::int64_t>& offsets)
{
    Address addr = base;
    for (std::int64_t off : offsets) {
        auto v = std::get<std::uint64_t>(read_value(proc, addr, ValueType::Ptr));
        addr = v + static_cast<std::uint64_t>(off);
        if (!proc.is_64bit()) addr &= 0xFFFFFFFFull;
    }
    return addr;
}

}  // namespace memcore
