// memcore/scanner.hpp -- FROZEN API CONTRACT: value scans (Cheat-Engine style) and AOB/string
// scans.
#pragma once
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "memcore/process.hpp"
#include "memcore/reader.hpp"
#include "memcore/types.hpp"

namespace memcore {

enum class CompareOp {
    Exact,
    Greater,
    Less,
    Between,
    Changed,
    Unchanged,
    Increased,
    Decreased,
    Unknown
};

// Case-insensitive: "exact"|"equal"|"==", "greater"|"gt"|">", "less"|"lt"|"<", "between",
// "changed", "unchanged", "increased", "decreased", "unknown". Throws MemoryError otherwise.
CompareOp parse_compare(std::string_view s);

struct ScanHit {
    Address address = 0;
    ScalarValue previous;  // value stored at last scan
    ScalarValue current;   // value re-read now (0 if now unreadable)
};

// Stateful value scanner. Not thread-safe; callers serialize access.
//
// first_scan: allowed ops are Exact, Greater, Less, Between (need value, and value2 for Between)
//   and Unknown (no value; every aligned slot in the filtered regions is a candidate).
//   Exact/Greater/Less/Between store matching addresses plus their value (packed in prev_values_).
//   Unknown stores a snapshot of all scanned regions instead of per-address entries;
//   total snapshot is capped at 512 MiB -> otherwise throws MemoryError. The snapshot is
//   converted to the address list on the first next_scan (which must then be a relational op:
//   Changed/Unchanged/Increased/Decreased, or Exact/Greater/Less/Between against value(s)).
// next_scan: filters existing candidates: re-reads each candidate; Exact/Greater/Less/Between
//   compare against the given value(s); Changed/Unchanged/Increased/Decreased compare against the
//   stored previous value. Survivors' stored value is updated to the new value.
//   Unreadable candidates are dropped. Throws MemoryError if no first_scan was done.
// alignment: bytes between candidate slots; 0 = natural (== value_size). Candidates never
//   straddle region boundaries.
// Result cap: at most 50,000,000 candidates are stored (throws MemoryError beyond that).
// Float compare: Exact uses relative epsilon 1e-5 (|a-b| <= 1e-5 * max(1,|a|,|b|));
//   Changed/Unchanged use exact bit inequality/equality.
// Return value of both scans: number of remaining candidates (== count()).
class ValueScanner {
   public:
    ValueScanner(std::shared_ptr<Process> proc, ValueType type);

    std::size_t first_scan(CompareOp op, std::optional<ScalarValue> value,
                           std::optional<ScalarValue> value2, const RegionFilter& filter,
                           std::size_t alignment);
    std::size_t next_scan(CompareOp op, std::optional<ScalarValue> value,
                          std::optional<ScalarValue> value2);

    std::size_t count() const;
    // Page of candidates [offset, offset+limit) in ascending address order; `current` is
    // re-read from the target at call time.
    std::vector<ScanHit> results(std::size_t offset, std::size_t limit) const;
    ValueType type() const;

   private:
    std::shared_ptr<Process> proc_;
    ValueType type_;
    std::vector<Address> addrs_;             // candidate addresses, ascending
    std::vector<std::uint8_t> prev_values_;  // packed: addrs_.size() * value_size bytes
    // Unknown first-scan snapshot (cleared once converted by next_scan).
    struct Snapshot {
        Address base = 0;
        std::vector<std::uint8_t> data;
    };
    std::vector<Snapshot> snapshots_;
    std::size_t alignment_ = 0;  // effective alignment of the first scan
    bool has_scan_ = false;
};

struct PatternMatch {
    Address address = 0;
    std::string module;
};

// Array-of-bytes pattern. mask[i] == true means bytes[i] must match; false = wildcard.
struct BytePattern {
    std::vector<std::uint8_t> bytes;
    std::vector<bool> mask;
    // "48 8B ?? 05", "48 8B ? 05", "488B??05" -> wildcards are "?" or "??". Hex is
    // case-insensitive. Throws MemoryError on malformed input or empty pattern.
    static BytePattern parse(std::string_view aob);
};

// Scans regions matching filter; returns up to max_results addresses in ascending order.
// Handles matches spanning chunk boundaries inside a region.
std::vector<Address> scan_pattern(const Process& proc, const BytePattern& pattern,
                                  const RegionFilter& filter, std::size_t max_results);

// Searches for utf8_text encoded as encoding ("utf8"|"utf16"|"ascii"). case_sensitive=false
// folds ASCII letters only. Returns up to max_results addresses (ascending).
std::vector<Address> scan_string(const Process& proc, std::string_view utf8_text,
                                 std::string_view encoding, bool case_sensitive,
                                 const RegionFilter& filter, std::size_t max_results);

}  // namespace memcore
