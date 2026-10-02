// memcore/process.hpp -- FROZEN API CONTRACT: process enumeration and read-only access.
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "memcore/types.hpp"

namespace memcore {

// Snapshot of all running processes (Toolhelp). Never throws on access problems.
std::vector<ProcessInfo> list_processes();

// RAII wrapper around a process HANDLE opened for READ-ONLY inspection.
// All methods are const and thread-safe (they only issue read syscalls).
class Process {
   public:
    // Opens with PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, falling back to
    // PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_VM_READ. Throws MemoryError on failure.
    explicit Process(std::uint32_t pid);
    ~Process();
    Process(const Process&) = delete;
    Process& operator=(const Process&) = delete;
    Process(Process&&) noexcept;
    Process& operator=(Process&&) noexcept;

    std::uint32_t pid() const;
    bool is_64bit() const;
    std::string name() const;  // exe file name
    std::string path() const;  // full image path
    bool is_alive() const;     // false once the process has exited

    // Loaded modules (first entry is the main exe). Includes 32-bit modules for WOW64 targets.
    std::vector<ModuleInfo> modules() const;
    // Exact module-name match, ignoring case (no ".dll" guessing).
    std::optional<ModuleInfo> find_module(std::string_view name) const;

    // Walks VirtualQueryEx over [filter.start, filter.end). MEM_FREE regions are never returned.
    // Regions are returned in ascending address order, clipped to the [start,end) window.
    // RegionInfo::module is filled for image regions.
    std::vector<RegionInfo> regions(const RegionFilter& filter) const;

    // Reads exactly `size` bytes; throws MemoryError (with Win32 error) if any byte is unreadable.
    std::vector<std::uint8_t> read(Address addr, std::size_t size) const;
    // Best-effort read into `out` (capacity >= size), page by page. Unreadable pages are
    // zero-filled. Returns the number of bytes actually read (<= size).
    std::size_t read_partial(Address addr, std::uint8_t* out, std::size_t size) const;
    // Exact read into caller buffer; returns false on any failure. Never throws.
    bool try_read(Address addr, void* out, std::size_t size) const noexcept;

    // Parses an address expression (whitespace tolerated):
    //   "0x1234"          hex
    //   "1234"            decimal
    //   "game.dll"        module base (case-insensitive)
    //   "game.dll+0x10"   module base + offset
    //   "game.dll-0x10"   module base - offset
    // Offsets may be hex (0x prefix) or decimal. Throws MemoryError if unparsable / module not
    // found.
    Address resolve(std::string_view expr) const;

    // Raw HANDLE as void* (keeps <windows.h> out of headers). Do not close it.
    void* handle() const;

   private:
    void* handle_ = nullptr;
    std::uint32_t pid_ = 0;
    bool is_64bit_ = false;
};

}  // namespace memcore
