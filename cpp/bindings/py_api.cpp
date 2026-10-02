#include "py_api.hpp"

#include <cstdio>
#include <new>
#include <sstream>
#include <utility>
#include <variant>

#include <nanobind/stl/optional.h>
#include <nanobind/stl/shared_ptr.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/variant.h>
#include <nanobind/stl/vector.h>

namespace nb = nanobind;

namespace memcore {

// ---- private helpers

RegionFilter PyApi::make_filter(bool readable_only, std::optional<bool> writable,
                                std::optional<bool> executable, std::optional<std::string> type,
                                std::optional<std::string> module, Address start, Address end)
{
    RegionFilter f;
    f.readable_only = readable_only;
    f.writable = writable;
    f.executable = executable;
    f.type = std::move(type);
    f.module = std::move(module);
    f.start = start;
    f.end = end;
    return f;
}

nb::bytes PyApi::to_bytes(const std::vector<std::uint8_t>& v)
{
    return nb::bytes(reinterpret_cast<const char*>(v.data()), v.size());
}

std::string PyApi::hex(std::uint64_t v)
{
    char buf[32];
    std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
    return buf;
}

std::string PyApi::scalar_repr(const ScalarValue& v)
{
    std::ostringstream os;
    std::visit([&](auto x) { os << x; }, v);
    return os.str();
}

// ---- types

std::size_t PyApi::value_size(const std::string& type, bool is_64bit)
{
    return memcore::value_size(parse_value_type(type), is_64bit);
}

std::string PyApi::scanner_type(const ValueScanner& s) { return value_type_name(s.type()); }

// ---- __repr__

std::string PyApi::repr_process_info(const ProcessInfo& p)
{
    return "ProcessInfo(pid=" + std::to_string(p.pid) + ", name='" + p.name +
           "', ppid=" + std::to_string(p.ppid) + ", threads=" + std::to_string(p.threads) +
           ", is_64bit=" + (p.is_64bit ? "True" : "False") + ")";
}

std::string PyApi::repr_module_info(const ModuleInfo& m)
{
    return "ModuleInfo(name='" + m.name + "', base=" + hex(m.base) + ", size=" + hex(m.size) + ")";
}

std::string PyApi::repr_region_info(const RegionInfo& r)
{
    return "RegionInfo(base=" + hex(r.base) + ", size=" + hex(r.size) + ", protect='" +
           r.protect_str + "', type='" + r.type_str + "', module='" + r.module + "')";
}

std::string PyApi::repr_scan_hit(const ScanHit& h)
{
    return "ScanHit(address=" + hex(h.address) + ", previous=" + scalar_repr(h.previous) +
           ", current=" + scalar_repr(h.current) + ")";
}

// ---- Process

void PyApi::init_process(Process* self, std::uint32_t pid)
{
    nb::gil_scoped_release rel;
    new (self) Process(pid);
}

std::vector<RegionInfo> PyApi::regions(const Process& p, bool readable_only,
                                       std::optional<bool> writable, std::optional<bool> executable,
                                       std::optional<std::string> type,
                                       std::optional<std::string> module, Address start,
                                       Address end)
{
    auto f = make_filter(readable_only, writable, executable, std::move(type), std::move(module),
                         start, end);
    nb::gil_scoped_release rel;
    return p.regions(f);
}

nb::bytes PyApi::read(const Process& p, Address address, std::size_t size)
{
    std::vector<std::uint8_t> v;
    {
        nb::gil_scoped_release rel;
        v = p.read(address, size);
    }
    return to_bytes(v);
}

nb::tuple PyApi::read_partial(const Process& p, Address address, std::size_t size)
{
    std::vector<std::uint8_t> v(size);
    std::size_t n = 0;
    {
        nb::gil_scoped_release rel;
        n = p.read_partial(address, v.data(), size);
    }
    return nb::make_tuple(to_bytes(v), n);
}

// ---- reader

ScalarValue PyApi::read_value(const Process& p, Address address, const std::string& type)
{
    auto t = parse_value_type(type);
    nb::gil_scoped_release rel;
    return memcore::read_value(p, address, t);
}

std::vector<ScalarValue> PyApi::read_values(const Process& p, Address address,
                                            const std::string& type, std::size_t count)
{
    auto t = parse_value_type(type);
    nb::gil_scoped_release rel;
    return memcore::read_values(p, address, t, count);
}

ScalarValue PyApi::decode_value(const nb::bytes& data, const std::string& type, bool is_64bit)
{
    auto t = parse_value_type(type);
    if (data.size() < memcore::value_size(t, is_64bit))
        throw MemoryError("not enough bytes to decode value");
    return memcore::decode_value(reinterpret_cast<const std::uint8_t*>(data.c_str()), t, is_64bit);
}

nb::bytes PyApi::encode_value(ScalarValue value, const std::string& type, bool is_64bit)
{
    return to_bytes(memcore::encode_value(value, parse_value_type(type), is_64bit));
}

// ---- pattern / string scans

std::vector<Address> PyApi::scan_pattern(const Process& p, const std::string& pattern,
                                         bool readable_only, std::optional<bool> writable,
                                         std::optional<bool> executable,
                                         std::optional<std::string> type,
                                         std::optional<std::string> module, Address start,
                                         Address end, std::size_t max_results)
{
    auto pat = BytePattern::parse(pattern);
    auto f = make_filter(readable_only, writable, executable, std::move(type), std::move(module),
                         start, end);
    nb::gil_scoped_release rel;
    return memcore::scan_pattern(p, pat, f, max_results);
}

std::vector<Address> PyApi::scan_string(const Process& p, const std::string& text,
                                        const std::string& encoding, bool case_sensitive,
                                        bool readable_only, std::optional<bool> writable,
                                        std::optional<bool> executable,
                                        std::optional<std::string> type,
                                        std::optional<std::string> module, Address start,
                                        Address end, std::size_t max_results)
{
    auto f = make_filter(readable_only, writable, executable, std::move(type), std::move(module),
                         start, end);
    nb::gil_scoped_release rel;
    return memcore::scan_string(p, text, encoding, case_sensitive, f, max_results);
}

// ---- ValueScanner

void PyApi::init_scanner(ValueScanner* self, std::shared_ptr<Process> proc, const std::string& type)
{
    new (self) ValueScanner(std::move(proc), parse_value_type(type));
}

std::size_t PyApi::first_scan(ValueScanner& s, const std::string& compare,
                              std::optional<ScalarValue> value, std::optional<ScalarValue> value2,
                              bool readable_only, std::optional<bool> writable,
                              std::optional<bool> executable, std::optional<std::string> type,
                              std::optional<std::string> module, Address start, Address end,
                              std::size_t alignment)
{
    auto op = parse_compare(compare);
    auto f = make_filter(readable_only, writable, executable, std::move(type), std::move(module),
                         start, end);
    nb::gil_scoped_release rel;
    return s.first_scan(op, value, value2, f, alignment);
}

std::size_t PyApi::next_scan(ValueScanner& s, const std::string& compare,
                             std::optional<ScalarValue> value, std::optional<ScalarValue> value2)
{
    auto op = parse_compare(compare);
    nb::gil_scoped_release rel;
    return s.next_scan(op, value, value2);
}

}  // namespace memcore
