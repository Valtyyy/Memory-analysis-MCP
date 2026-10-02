// process.cpp -- read-only process access (Toolhelp, VirtualQueryEx, ReadProcessMemory).
#include "memcore/process.hpp"

#include <windows.h>

#include <tlhelp32.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <utility>

namespace memcore {

namespace {

std::string to_utf8(const wchar_t* w, int len = -1)
{
    if (!w) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w, len, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, len, s.data(), n, nullptr, nullptr);
    if (len == -1 && !s.empty() && s.back() == '\0') s.pop_back();
    return s;
}

char lower(char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); }

bool iequals(std::string_view a, std::string_view b)
{
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (lower(a[i]) != lower(b[i])) return false;
    return true;
}

std::string_view trim(std::string_view s)
{
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.remove_suffix(1);
    return s;
}

// Returns true if the process behind h is a native 64-bit process.
bool query_is_64bit(HANDLE h)
{
    using Fn2 = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
    // NOLINTNEXTLINE(misc-misplaced-const)
    static const Fn2 is_wow64_2 = reinterpret_cast<Fn2>(reinterpret_cast<void*>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2")));
    if (is_wow64_2) {
        USHORT pm = 0, nm = 0;
        if (is_wow64_2(h, &pm, &nm)) {
            bool native64 = nm == IMAGE_FILE_MACHINE_AMD64 || nm == IMAGE_FILE_MACHINE_ARM64;
            return pm == IMAGE_FILE_MACHINE_UNKNOWN && native64;
        }
        return false;
    }
    BOOL wow = FALSE;
    if (!IsWow64Process(h, &wow)) return false;
    if (wow) return false;
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    return si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
           si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64;
}

struct SnapHandle {
    HANDLE h;
    explicit SnapHandle(HANDLE x) : h(x) {}
    ~SnapHandle()
    {
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
    SnapHandle(const SnapHandle&) = delete;
    SnapHandle& operator=(const SnapHandle&) = delete;
};

bool parse_number(std::string_view s, std::uint64_t& out)
{
    s = trim(s);
    if (s.empty()) return false;
    unsigned base = 10;
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        base = 16;
        s.remove_prefix(2);
        if (s.empty()) return false;
    }
    std::uint64_t v = 0;
    for (char c : s) {
        unsigned d = 0;
        if (c >= '0' && c <= '9')
            d = static_cast<unsigned>(c - '0');
        else if (base == 16 && c >= 'a' && c <= 'f')
            d = static_cast<unsigned>(c - 'a' + 10);
        else if (base == 16 && c >= 'A' && c <= 'F')
            d = static_cast<unsigned>(c - 'A' + 10);
        else
            return false;
        if (v > (UINT64_MAX - d) / base) return false;  // overflow
        v = v * base + d;
    }
    out = v;
    return true;
}

bool is_writable(DWORD p)
{
    return p & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
}
bool is_executable(DWORD p)
{
    return p & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
}
bool is_readable_prot(DWORD p)
{
    if (p & (PAGE_GUARD | PAGE_NOACCESS)) return false;
    return (p & 0xFF) != 0;
}

}  // namespace

std::vector<ProcessInfo> list_processes()
{
    std::vector<ProcessInfo> out;
    SnapHandle snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (snap.h == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap.h, &pe)) return out;
    do {
        ProcessInfo pi;
        pi.pid = pe.th32ProcessID;
        pi.ppid = pe.th32ParentProcessID;
        pi.threads = pe.cntThreads;
        pi.name = to_utf8(pe.szExeFile);
        if (pi.pid != 0) {
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pi.pid);
            if (h) {
                pi.is_64bit = query_is_64bit(h);
                CloseHandle(h);
            }
        }
        out.push_back(std::move(pi));
    } while (Process32NextW(snap.h, &pe));
    return out;
}

Process::Process(std::uint32_t pid) : pid_(pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) throw MemoryError("cannot open process " + std::to_string(pid), GetLastError());
    handle_ = h;
    is_64bit_ = query_is_64bit(h);
}

Process::~Process()
{
    if (handle_) CloseHandle(static_cast<HANDLE>(handle_));
}

Process::Process(Process&& o) noexcept
    : handle_(std::exchange(o.handle_, nullptr)), pid_(o.pid_), is_64bit_(o.is_64bit_)
{
}

Process& Process::operator=(Process&& o) noexcept
{
    if (this != &o) {
        if (handle_) CloseHandle(static_cast<HANDLE>(handle_));
        handle_ = std::exchange(o.handle_, nullptr);
        pid_ = o.pid_;
        is_64bit_ = o.is_64bit_;
    }
    return *this;
}

std::uint32_t Process::pid() const { return pid_; }
bool Process::is_64bit() const { return is_64bit_; }
void* Process::handle() const { return handle_; }

std::string Process::path() const
{
    if (!handle_) return {};
    std::wstring buf(1024, L'\0');
    for (int i = 0; i < 6; ++i) {
        auto n = static_cast<DWORD>(buf.size());
        if (QueryFullProcessImageNameW(static_cast<HANDLE>(handle_), 0, buf.data(), &n)) {
            return to_utf8(buf.data(), static_cast<int>(n));
        }
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) break;
        buf.resize(buf.size() * 2);
    }
    return {};
}

std::string Process::name() const
{
    std::string p = path();
    if (!p.empty()) {
        auto pos = p.find_last_of("\\/");
        return pos == std::string::npos ? p : p.substr(pos + 1);
    }
    for (const auto& pi : list_processes())
        if (pi.pid == pid_) return pi.name;
    return {};
}

bool Process::is_alive() const
{
    if (!handle_) return false;
    DWORD code = 0;
    if (!GetExitCodeProcess(static_cast<HANDLE>(handle_), &code)) return false;
    return code == STILL_ACTIVE;
}

std::vector<ModuleInfo> Process::modules() const
{
    SnapHandle snap(INVALID_HANDLE_VALUE);
    DWORD err = 0;
    for (int attempt = 0; attempt < 20; ++attempt) {
        snap.h = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid_);
        if (snap.h != INVALID_HANDLE_VALUE) break;
        err = GetLastError();
        if (err != ERROR_BAD_LENGTH) break;
        Sleep(5);
    }
    if (snap.h == INVALID_HANDLE_VALUE) throw MemoryError("cannot enumerate modules", err);
    std::vector<ModuleInfo> out;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    if (!Module32FirstW(snap.h, &me)) return out;
    do {
        ModuleInfo mi;
        mi.name = to_utf8(me.szModule);
        mi.path = to_utf8(me.szExePath);
        mi.base = reinterpret_cast<std::uintptr_t>(me.modBaseAddr);
        mi.size = me.modBaseSize;
        out.push_back(std::move(mi));
    } while (Module32NextW(snap.h, &me));
    return out;
}

std::optional<ModuleInfo> Process::find_module(std::string_view name) const
{
    for (auto& m : modules())
        if (iequals(m.name, name)) return m;
    return std::nullopt;
}

std::vector<RegionInfo> Process::regions(const RegionFilter& f) const
{
    std::vector<RegionInfo> out;
    std::vector<ModuleInfo> mods;
    try {
        mods = modules();
    } catch (const MemoryError&) {  // NOLINT(bugprone-empty-catch): module list is best-effort
    }

    Address start = f.start, end = f.end;
    if (f.module) {
        const ModuleInfo* found = nullptr;
        for (auto& m : mods)
            if (iequals(m.name, *f.module)) {
                found = &m;
                break;
            }
        if (!found) return out;
        start = std::max<Address>(start, found->base);
        end = std::min<Address>(end, found->base + found->size);
    }
    std::string want_type;
    if (f.type) {
        want_type = *f.type;
        std::ranges::transform(want_type, want_type.begin(), lower);
    }

    Address addr = start;
    while (addr < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQueryEx(static_cast<HANDLE>(handle_),
                           reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(addr)), &mbi,
                           sizeof(mbi)) == 0)
            break;
        auto rbase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        Address rsize = mbi.RegionSize;
        Address rend = rbase + rsize;
        bool overflow = rend < rbase;
        if (overflow) rend = UINT64_MAX;

        if (mbi.State == MEM_COMMIT) {
            DWORD p = mbi.Protect;
            bool ok = true;
            if (f.readable_only && !is_readable_prot(p)) ok = false;
            if (ok && f.writable && is_writable(p) != *f.writable) ok = false;
            if (ok && f.executable && is_executable(p) != *f.executable) ok = false;
            std::string tstr = mbi.Type == MEM_IMAGE    ? "image"
                               : mbi.Type == MEM_MAPPED ? "mapped"
                                                        : "private";
            if (ok && f.type && tstr != want_type) ok = false;
            if (ok) {
                RegionInfo ri;
                ri.base = std::max(rbase, start);
                Address e = std::min(rend, end);
                ri.size = e - ri.base;
                ri.state = mbi.State;
                ri.protect = p;
                ri.type = mbi.Type;
                ri.protect_str = std::string(
                    1, is_readable_prot(p & ~static_cast<DWORD>(PAGE_GUARD)) ? 'R' : '-');
                ri.protect_str += is_writable(p) ? 'W' : '-';
                ri.protect_str += is_executable(p) ? 'X' : '-';
                if (p & PAGE_GUARD) ri.protect_str += 'G';
                ri.type_str = tstr;
                if (mbi.Type == MEM_IMAGE) {
                    auto abase = reinterpret_cast<std::uintptr_t>(mbi.AllocationBase);
                    for (auto& m : mods)
                        if (rbase >= m.base && rbase < m.base + m.size) {
                            ri.module = m.name;
                            break;
                        }
                    if (ri.module.empty())  // e.g. pages outside the module's reported size
                        for (auto& m : mods)
                            if (abase == m.base) {
                                ri.module = m.name;
                                break;
                            }
                }
                if (ri.size > 0) out.push_back(std::move(ri));
            }
        }
        if (overflow || rend <= addr) break;
        addr = rend;
    }
    return out;
}

std::vector<std::uint8_t> Process::read(Address addr, std::size_t size) const
{
    std::vector<std::uint8_t> buf(size);
    if (size == 0) return buf;
    SIZE_T got = 0;
    if (!ReadProcessMemory(static_cast<HANDLE>(handle_),
                           reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(addr)), buf.data(),
                           size, &got)) {
        DWORD err = GetLastError();
        char hex[32];
        std::snprintf(hex, sizeof hex, "0x%llX", static_cast<unsigned long long>(addr));
        throw MemoryError(std::string("cannot read ") + std::to_string(size) + " bytes at " + hex,
                          err);
    }
    if (got != size) throw MemoryError("short read at address");
    return buf;
}

bool Process::try_read(Address addr, void* out, std::size_t size) const noexcept
{
    if (size == 0) return true;
    SIZE_T got = 0;
    return ReadProcessMemory(static_cast<HANDLE>(handle_),
                             reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(addr)), out,
                             size, &got) &&
           got == size;
}

std::size_t Process::read_partial(Address addr, std::uint8_t* out, std::size_t size) const
{
    if (size == 0) return 0;
    if (try_read(addr, out, size)) return size;
    constexpr std::size_t kPage = 4096;
    std::size_t done = 0, total = 0;
    while (done < size) {
        Address a = addr + done;
        std::size_t chunk = std::min<std::size_t>(size - done, kPage - (a % kPage));
        if (try_read(a, out + done, chunk))
            total += chunk;
        else
            std::fill(out + done, out + done + chunk, std::uint8_t{0});
        done += chunk;
    }
    return total;
}

Address Process::resolve(std::string_view expr) const
{
    std::string_view e = trim(expr);
    if (e.empty()) throw MemoryError("empty address expression");
    std::uint64_t v = 0;
    if (parse_number(e, v)) return v;
    if (auto m = find_module(e)) return m->base;
    // module(+|-)offset: try splitting at each +/- from the right (module names may contain '-').
    for (size_t i = e.size(); i-- > 1;) {
        if (e[i] != '+' && e[i] != '-') continue;
        std::string_view left = trim(e.substr(0, i)), right = e.substr(i + 1);
        std::uint64_t off = 0;
        if (!parse_number(right, off)) continue;
        auto m = find_module(left);
        if (!m) continue;
        return e[i] == '+' ? m->base + off : m->base - off;
    }
    throw MemoryError("cannot resolve address expression: " + std::string(expr));
}

}  // namespace memcore
