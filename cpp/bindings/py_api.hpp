// Python-facing glue for the memcore library.
//
// Every function exposed to Python that needs adaptation (string -> enum parsing, RegionFilter
// assembly from keyword arguments, bytes conversion, GIL release, __repr__) lives here as a
// static member, so module.cpp only declares bindings.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "memcore/process.hpp"
#include "memcore/reader.hpp"
#include "memcore/scanner.hpp"
#include "memcore/types.hpp"
#include <nanobind/nanobind.h>

namespace memcore {

class PyApi {
   public:
    PyApi() = delete;

    // ---- types
    static std::size_t value_size(const std::string& type, bool is_64bit);
    static std::string scanner_type(const ValueScanner& s);

    // ---- __repr__
    static std::string repr_process_info(const ProcessInfo& p);
    static std::string repr_module_info(const ModuleInfo& m);
    static std::string repr_region_info(const RegionInfo& r);
    static std::string repr_scan_hit(const ScanHit& h);

    // ---- Process
    static void init_process(Process* self, std::uint32_t pid);
    static std::vector<RegionInfo> regions(const Process& p, bool readable_only,
                                           std::optional<bool> writable,
                                           std::optional<bool> executable,
                                           std::optional<std::string> type,
                                           std::optional<std::string> module, Address start,
                                           Address end);
    static nanobind::bytes read(const Process& p, Address address, std::size_t size);
    // Returns (data zero-filled to `size`, bytes_actually_read).
    static nanobind::tuple read_partial(const Process& p, Address address, std::size_t size);

    // ---- reader
    static ScalarValue read_value(const Process& p, Address address, const std::string& type);
    static std::vector<ScalarValue> read_values(const Process& p, Address address,
                                                const std::string& type, std::size_t count);
    static ScalarValue decode_value(const nanobind::bytes& data, const std::string& type,
                                    bool is_64bit);
    static nanobind::bytes encode_value(ScalarValue value, const std::string& type, bool is_64bit);

    // ---- pattern / string scans
    static std::vector<Address> scan_pattern(const Process& p, const std::string& pattern,
                                             bool readable_only, std::optional<bool> writable,
                                             std::optional<bool> executable,
                                             std::optional<std::string> type,
                                             std::optional<std::string> module, Address start,
                                             Address end, std::size_t max_results);
    static std::vector<Address> scan_string(const Process& p, const std::string& text,
                                            const std::string& encoding, bool case_sensitive,
                                            bool readable_only, std::optional<bool> writable,
                                            std::optional<bool> executable,
                                            std::optional<std::string> type,
                                            std::optional<std::string> module, Address start,
                                            Address end, std::size_t max_results);

    // ---- ValueScanner
    static void init_scanner(ValueScanner* self, std::shared_ptr<Process> proc,
                             const std::string& type);
    static std::size_t first_scan(ValueScanner& s, const std::string& compare,
                                  std::optional<ScalarValue> value,
                                  std::optional<ScalarValue> value2, bool readable_only,
                                  std::optional<bool> writable, std::optional<bool> executable,
                                  std::optional<std::string> type,
                                  std::optional<std::string> module, Address start, Address end,
                                  std::size_t alignment);
    static std::size_t next_scan(ValueScanner& s, const std::string& compare,
                                 std::optional<ScalarValue> value,
                                 std::optional<ScalarValue> value2);

   private:
    static RegionFilter make_filter(bool readable_only, std::optional<bool> writable,
                                    std::optional<bool> executable, std::optional<std::string> type,
                                    std::optional<std::string> module, Address start, Address end);
    static nanobind::bytes to_bytes(const std::vector<std::uint8_t>& v);
    static std::string hex(std::uint64_t v);
    static std::string scalar_repr(const ScalarValue& v);
};

}  // namespace memcore
