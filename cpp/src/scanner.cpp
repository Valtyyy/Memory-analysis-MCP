// memcore scanner: value scans (Cheat-Engine style), AOB pattern scans and string scans.
// Read-only: only Process::regions/read_partial/try_read are used.
#include "memcore/scanner.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cmath>
#include <cstring>
#include <exception>
#include <mutex>
#include <thread>
#include <type_traits>

namespace memcore {

namespace {

constexpr std::size_t kChunk = 4u << 20;  // 4 MiB work unit
constexpr std::size_t kPage = 4096;
constexpr std::size_t kMaxCandidates = 50'000'000;
constexpr std::uint64_t kMaxSnapshotBytes = 512ull << 20;

struct Run {
    std::size_t off, len;
};

// Reads [addr, addr+len) into buf. `runs` receives the byte ranges that were really readable
// (zero-filled gaps are excluded so unreadable pages never produce false matches).
void read_runs(const Process& p, Address addr, std::uint8_t* buf, std::size_t len,
               std::vector<Run>& runs)
{
    runs.clear();
    if (len == 0) return;
    std::size_t got = p.read_partial(addr, buf, len);
    if (got == len) {
        runs.push_back({0, len});
        return;
    }
    if (got == 0) return;
    std::size_t off = 0;
    while (off < len) {
        std::size_t to_page = kPage - static_cast<std::size_t>((addr + off) % kPage);
        std::size_t piece = std::min(to_page, len - off);
        if (p.try_read(addr + off, buf + off, piece)) {
            if (!runs.empty() && runs.back().off + runs.back().len == off)
                runs.back().len += piece;
            else
                runs.push_back({off, piece});
        }
        off += piece;
    }
}

// Runs f(i) for i in [0, n) on a small thread pool. Stops early when `stop` becomes true.
template <class F>
void parallel_for(std::size_t n, std::atomic<bool>& stop, F&& f)
{
    std::size_t nt = std::min<std::size_t>(std::max(1u, std::thread::hardware_concurrency()), n);
    if (nt <= 1) {
        for (std::size_t i = 0; i < n && !stop.load(); ++i) f(i);
        return;
    }
    std::atomic<std::size_t> next{0};
    std::exception_ptr err;
    std::mutex m;
    auto worker = [&] {
        for (;;) {
            if (stop.load()) return;
            std::size_t i = next.fetch_add(1);
            if (i >= n) return;
            try {
                f(i);
            } catch (...) {
                std::scoped_lock lk(m);
                if (!err) err = std::current_exception();
                stop = true;
                return;
            }
        }
    };
    std::vector<std::thread> th;
    for (std::size_t i = 1; i < nt; ++i) th.emplace_back(worker);
    worker();
    for (auto& t : th) t.join();
    if (err) std::rethrow_exception(err);
}

inline Address round_up(Address a, std::size_t align)
{
    Address r = a % align;
    return r ? a + (align - r) : a;
}

inline Address region_end(const RegionInfo& r)
{
    return (r.base + r.size < r.base) ? UINT64_MAX : r.base + r.size;
}

// ---------------------------------------------------------------------------------------------
// Typed comparison
// ---------------------------------------------------------------------------------------------

template <class T>
struct Cmp {
    CompareOp op{};
    T v1{}, v2{};
};

template <class T>
inline bool test(const Cmp<T>& c, T cur, T prev)
{
    switch (c.op) {
        case CompareOp::Exact:
            if constexpr (std::is_floating_point_v<T>) {
                if (cur == c.v1) return true;
                auto a = static_cast<double>(cur), b = static_cast<double>(c.v1);
                if (std::isnan(a) || std::isnan(b) || std::isinf(a) || std::isinf(b)) return false;
                double scale = std::max({1.0, std::fabs(a), std::fabs(b)});
                return std::fabs(a - b) <= 1e-5 * scale;
            } else {
                return cur == c.v1;
            }
        case CompareOp::Greater:
            return cur > c.v1;
        case CompareOp::Less:
            return cur < c.v1;
        case CompareOp::Between:
            return cur >= c.v1 && cur <= c.v2;
        case CompareOp::Changed:
            // NOLINTNEXTLINE(bugprone-suspicious-memory-comparison): bitwise on purpose
            return std::memcmp(&cur, &prev, sizeof(T)) != 0;
        case CompareOp::Unchanged:
            // NOLINTNEXTLINE(bugprone-suspicious-memory-comparison): bitwise on purpose
            return std::memcmp(&cur, &prev, sizeof(T)) == 0;
        case CompareOp::Increased:
            return cur > prev;
        case CompareOp::Decreased:
            return cur < prev;
        case CompareOp::Unknown:
            return true;
    }
    return false;
}

template <class T>
T convert(const ScalarValue& v)
{
    return std::visit(
        [](auto x) -> T {
            using X = decltype(x);
            // NOLINTNEXTLINE(bugprone-branch-clone)
            if constexpr (std::is_floating_point_v<T>) {
                return static_cast<T>(x);
            } else if constexpr (std::is_same_v<X, double>) {
                if (std::isnan(x)) return 0;
                if (x < 0)
                    return static_cast<T>(x > -9.2e18 ? static_cast<std::int64_t>(x) : INT64_MIN);
                return static_cast<T>(x < 1.8e19 ? static_cast<std::uint64_t>(x) : UINT64_MAX);
            } else {
                return static_cast<T>(x);
            }
        },
        v);
}

template <class T>
struct Tag {
    using type = T;
};

template <class F>
void with_type(ValueType t, bool is64, F&& f)
{
    switch (t) {
        case ValueType::I8:
            f(Tag<std::int8_t>{});
            return;
        case ValueType::U8:
            f(Tag<std::uint8_t>{});
            return;
        case ValueType::I16:
            f(Tag<std::int16_t>{});
            return;
        case ValueType::U16:
            f(Tag<std::uint16_t>{});
            return;
        case ValueType::I32:
            f(Tag<std::int32_t>{});
            return;
        case ValueType::U32:
            f(Tag<std::uint32_t>{});
            return;
        case ValueType::I64:
            f(Tag<std::int64_t>{});
            return;
        case ValueType::U64:
            f(Tag<std::uint64_t>{});
            return;
        case ValueType::F32:
            f(Tag<float>{});
            return;
        case ValueType::F64:
            f(Tag<double>{});
            return;
        case ValueType::Ptr:
            if (is64)
                f(Tag<std::uint64_t>{});
            else
                f(Tag<std::uint32_t>{});
            return;
    }
    throw MemoryError("invalid value type");
}

template <class T>
Cmp<T> make_cmp(CompareOp op, const std::optional<ScalarValue>& v1,
                const std::optional<ScalarValue>& v2)
{
    Cmp<T> c;
    c.op = op;
    if (v1) c.v1 = convert<T>(*v1);
    if (v2) c.v2 = convert<T>(*v2);
    if (op == CompareOp::Between && c.v1 > c.v2) std::swap(c.v1, c.v2);
    return c;
}

bool needs_value(CompareOp op)
{
    return op == CompareOp::Exact || op == CompareOp::Greater || op == CompareOp::Less ||
           op == CompareOp::Between;
}

void check_values(CompareOp op, const std::optional<ScalarValue>& v1,
                  const std::optional<ScalarValue>& v2)
{
    if (needs_value(op) && !v1) throw MemoryError("this compare operation requires a value");
    if (op == CompareOp::Between && !v2)
        throw MemoryError("'between' requires both value and value2");
}

// Work unit for value scans: owns slots whose address is in [base, own_end) on the alignment
// grid, with slot + size <= region_end.
struct VUnit {
    Address base, own_end, region_end;
};

std::vector<VUnit> make_value_units(const std::vector<RegionInfo>& regs, std::size_t align,
                                    std::size_t sz)
{
    std::vector<VUnit> units;
    std::size_t step = std::max<std::size_t>(align, (kChunk / align) * align);
    for (const auto& r : regs) {
        Address re = region_end(r);
        Address s0 = round_up(r.base, align);
        if (s0 > re || re - s0 < sz) continue;
        for (Address a = s0; re - a >= sz;) {
            Address oe = (re - a > step) ? a + step : re;
            units.push_back({a, oe, re});
            if (oe == re) break;
            a = oe;
        }
    }
    return units;
}

// Number of bytes to read for a unit (covers all owned slots).
std::size_t unit_read_len(const VUnit& u, std::size_t align, std::size_t sz)
{
    Address last = u.base + ((u.own_end - 1 - u.base) / align) * align;
    if (u.region_end - last < sz) last = u.base + ((u.region_end - sz - u.base) / align) * align;
    return static_cast<std::size_t>(last + sz - u.base);
}

std::size_t slot_count(Address base, std::size_t len, std::size_t align, std::size_t sz)
{
    Address first = round_up(base, align);
    Address end = base + len;
    if (first > end || end - first < sz) return 0;
    return static_cast<std::size_t>((end - sz - first) / align) + 1;
}

// ---------------------------------------------------------------------------------------------
// Byte matcher (patterns & strings)
// ---------------------------------------------------------------------------------------------

struct Matcher {
    std::vector<std::uint8_t> bytes;  // folded to lowercase where flag==2
    std::vector<std::uint8_t> flags;  // 0 wildcard, 1 exact, 2 ASCII case-insensitive
    long anchor = -1;                 // index of an exact byte used for memchr

    void finish()
    {
        long best = -1;
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            if (flags[i] != 1) continue;
            if (best < 0) best = static_cast<long>(i);
            if (bytes[i] != 0) {
                best = static_cast<long>(i);
                break;
            }
        }
        anchor = best;
    }

    bool match_at(const std::uint8_t* p) const
    {
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            std::uint8_t f = flags[i];
            if (f == 0) continue;
            std::uint8_t d = p[i];
            if (f == 2 && d >= 'A' && d <= 'Z') d = static_cast<std::uint8_t>(d + 32);
            if (d != bytes[i]) return false;
        }
        return true;
    }

    // Finds start positions in [0, max_start) such that the pattern fits inside [0, len).
    template <class Sink>
    void search(const std::uint8_t* d, std::size_t len, std::size_t max_start, Sink&& sink) const
    {
        std::size_t n = bytes.size();
        if (len < n) return;
        std::size_t last = std::min(len - n + 1, max_start);  // exclusive
        if (last == 0) return;
        if (anchor >= 0) {
            std::uint8_t ab = bytes[static_cast<std::size_t>(anchor)];
            auto k = static_cast<std::size_t>(anchor);
            std::size_t pos = 0;
            while (pos < last) {
                const void* f = std::memchr(d + pos + k, ab, last - pos);
                if (!f) break;
                std::size_t hit = static_cast<const std::uint8_t*>(f) - (d + k);
                if (match_at(d + hit))
                    if (!sink(hit)) return;
                pos = hit + 1;
            }
        } else {
            for (std::size_t pos = 0; pos < last; ++pos)
                if (match_at(d + pos))
                    if (!sink(pos)) return;
        }
    }
};

struct PUnit {
    Address base;      // first owned start address
    Address own_end;   // exclusive end of owned start addresses
    Address read_end;  // exclusive end of bytes to read
};

std::vector<Address> run_matcher(const Process& proc, const Matcher& m, const RegionFilter& filter,
                                 std::size_t max_results)
{
    std::vector<Address> out;
    if (max_results == 0) return out;
    const std::size_t plen = m.bytes.size();
    auto regs = proc.regions(filter);
    std::vector<PUnit> units;
    for (const auto& r : regs) {
        Address re = region_end(r);
        if (re - r.base < plen) continue;
        Address last_start_excl = re - plen + 1;
        for (Address a = r.base; a < last_start_excl;) {
            Address oe = (last_start_excl - a > kChunk) ? a + kChunk : last_start_excl;
            units.push_back({a, oe, std::min<Address>(re, oe + plen - 1)});
            a = oe;
        }
    }
    std::vector<std::vector<Address>> res(units.size());
    std::vector<char> done(units.size(), 0);
    std::size_t prefix = 0, prefix_hits = 0;
    std::mutex mu;
    std::atomic<bool> stop{false};
    parallel_for(units.size(), stop, [&](std::size_t i) {
        thread_local std::vector<std::uint8_t> buf;
        thread_local std::vector<Run> runs;
        const PUnit& u = units[i];
        auto len = static_cast<std::size_t>(u.read_end - u.base);
        auto own = static_cast<std::size_t>(u.own_end - u.base);
        if (buf.size() < len) buf.resize(len);
        read_runs(proc, u.base, buf.data(), len, runs);
        auto& local = res[i];
        for (const Run& r : runs) {
            if (r.off >= own) continue;
            m.search(buf.data() + r.off, r.len, own - r.off, [&](std::size_t pos) {
                local.push_back(u.base + r.off + pos);
                return local.size() < max_results;
            });
        }
        std::scoped_lock lk(mu);
        done[i] = 1;
        while (prefix < units.size() && done[prefix]) prefix_hits += res[prefix++].size();
        if (prefix_hits >= max_results) stop = true;
    });
    for (auto& v : res) {
        for (Address a : v) {
            out.push_back(a);
            if (out.size() >= max_results) return out;
        }
    }
    return out;
}

int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::string lower(std::string_view s)
{
    std::string k(s);
    std::ranges::transform(k, k.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return k;
}

}  // namespace

CompareOp parse_compare(std::string_view s)
{
    std::string k(s);
    std::ranges::transform(k, k.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (k == "exact" || k == "equal" || k == "==") return CompareOp::Exact;
    if (k == "greater" || k == "gt" || k == ">") return CompareOp::Greater;
    if (k == "less" || k == "lt" || k == "<") return CompareOp::Less;
    if (k == "between") return CompareOp::Between;
    if (k == "changed") return CompareOp::Changed;
    if (k == "unchanged") return CompareOp::Unchanged;
    if (k == "increased") return CompareOp::Increased;
    if (k == "decreased") return CompareOp::Decreased;
    if (k == "unknown") return CompareOp::Unknown;
    throw MemoryError("unknown compare op: " + std::string(s));
}

// ---------------------------------------------------------------------------------------------
// ValueScanner
// ---------------------------------------------------------------------------------------------

ValueScanner::ValueScanner(std::shared_ptr<Process> proc, ValueType type)
    : proc_(std::move(proc)), type_(type)
{
}

ValueType ValueScanner::type() const { return type_; }

std::size_t ValueScanner::count() const
{
    if (!snapshots_.empty()) {
        std::size_t sz = value_size(type_, proc_->is_64bit());
        std::size_t n = 0;
        for (const auto& s : snapshots_) n += slot_count(s.base, s.data.size(), alignment_, sz);
        return n;
    }
    return addrs_.size();
}

std::size_t ValueScanner::first_scan(CompareOp op, std::optional<ScalarValue> value,
                                     std::optional<ScalarValue> value2, const RegionFilter& filter,
                                     std::size_t alignment)
{
    if (op == CompareOp::Changed || op == CompareOp::Unchanged || op == CompareOp::Increased ||
        op == CompareOp::Decreased)
        throw MemoryError(
            "changed/unchanged/increased/decreased are only valid after a first scan; use "
            "exact/greater/less/between/unknown for the first scan");
    check_values(op, value, value2);

    const Process& proc = *proc_;
    const bool is64 = proc.is_64bit();
    const std::size_t sz = value_size(type_, is64);
    const std::size_t align = alignment ? alignment : sz;

    auto regs = proc.regions(filter);
    auto units = make_value_units(regs, align, sz);

    std::vector<Address> addrs;
    std::vector<std::uint8_t> vals;
    std::vector<Snapshot> snaps;
    std::atomic<bool> stop{false};

    if (op == CompareOp::Unknown) {
        std::uint64_t total = 0;
        for (const auto& u : units) total += unit_read_len(u, align, sz);
        if (total > kMaxSnapshotBytes)
            throw MemoryError("unknown-value snapshot would need " + std::to_string(total >> 20) +
                              " MiB (limit 512 MiB); use a narrower region filter "
                              "(module/start/end/writable/type) or a larger alignment");
        std::vector<std::vector<Snapshot>> per(units.size());
        parallel_for(units.size(), stop, [&](std::size_t i) {
            thread_local std::vector<Run> runs;
            const VUnit& u = units[i];
            std::size_t len = unit_read_len(u, align, sz);
            std::vector<std::uint8_t> buf(len);
            read_runs(proc, u.base, buf.data(), len, runs);
            for (const Run& r : runs) {
                if (slot_count(u.base + r.off, r.len, align, sz) == 0) continue;
                Snapshot s;
                s.base = u.base + r.off;
                s.data.assign(buf.begin() + r.off, buf.begin() + r.off + r.len);
                per[i].push_back(std::move(s));
            }
        });
        for (auto& v : per)
            for (auto& s : v) snaps.push_back(std::move(s));
    } else {
        std::vector<std::vector<Address>> pa(units.size());
        std::vector<std::vector<std::uint8_t>> pv(units.size());
        std::atomic<std::size_t> total{0};
        with_type(type_, is64, [&](auto tag) {
            using T = decltype(tag)::type;
            Cmp<T> c = make_cmp<T>(op, value, value2);
            parallel_for(units.size(), stop, [&](std::size_t i) {
                thread_local std::vector<std::uint8_t> buf;
                thread_local std::vector<Run> runs;
                const VUnit& u = units[i];
                std::size_t len = unit_read_len(u, align, sz);
                if (buf.size() < len) buf.resize(len);
                read_runs(proc, u.base, buf.data(), len, runs);
                auto& A = pa[i];
                auto& V = pv[i];
                for (const Run& r : runs) {
                    const std::uint8_t* d = buf.data() + r.off;
                    Address base = u.base + r.off;
                    Address first = round_up(base, align);
                    for (auto off = static_cast<std::size_t>(first - base);
                         off + sizeof(T) <= r.len; off += align) {
                        T x;
                        std::memcpy(&x, d + off, sizeof(T));
                        if (test(c, x, x)) {
                            A.push_back(base + off);
                            V.insert(V.end(), d + off, d + off + sizeof(T));
                        }
                    }
                }
                if (total.fetch_add(A.size()) + A.size() > kMaxCandidates) stop = true;
            });
        });
        std::size_t n = 0;
        for (auto& v : pa) n += v.size();
        if (n > kMaxCandidates)
            throw MemoryError(
                "too many matches (more than 50,000,000 candidates); use a "
                "narrower region filter (module/start/end/writable/type), a larger "
                "alignment, or a more specific value");
        addrs.reserve(n);
        vals.reserve(n * sz);
        for (std::size_t i = 0; i < pa.size(); ++i) {
            addrs.insert(addrs.end(), pa[i].begin(), pa[i].end());
            vals.insert(vals.end(), pv[i].begin(), pv[i].end());
            std::vector<Address>().swap(pa[i]);
            std::vector<std::uint8_t>().swap(pv[i]);
        }
    }

    addrs_ = std::move(addrs);
    prev_values_ = std::move(vals);
    snapshots_ = std::move(snaps);
    alignment_ = align;
    has_scan_ = true;
    return count();
}

std::size_t ValueScanner::next_scan(CompareOp op, std::optional<ScalarValue> value,
                                    std::optional<ScalarValue> value2)
{
    if (!has_scan_) throw MemoryError("no first scan has been done yet");
    if (op == CompareOp::Unknown) throw MemoryError("'unknown' is only valid for a first scan");
    check_values(op, value, value2);

    const Process& proc = *proc_;
    const bool is64 = proc.is_64bit();
    const std::size_t sz = value_size(type_, is64);

    if (!snapshots_.empty()) {
        // Convert the snapshot into a candidate list while filtering.
        std::vector<std::vector<Address>> pa(snapshots_.size());
        std::vector<std::vector<std::uint8_t>> pv(snapshots_.size());
        std::atomic<std::size_t> total{0};
        std::atomic<bool> stop{false};
        const std::size_t align = alignment_;
        with_type(type_, is64, [&](auto tag) {
            using T = decltype(tag)::type;
            Cmp<T> c = make_cmp<T>(op, value, value2);
            parallel_for(snapshots_.size(), stop, [&](std::size_t i) {
                thread_local std::vector<std::uint8_t> buf;
                thread_local std::vector<Run> runs;
                const Snapshot& s = snapshots_[i];
                if (buf.size() < s.data.size()) buf.resize(s.data.size());
                read_runs(proc, s.base, buf.data(), s.data.size(), runs);
                auto& A = pa[i];
                auto& V = pv[i];
                for (const Run& r : runs) {
                    Address rbase = s.base + r.off;
                    Address first = round_up(rbase, align);
                    for (auto off = static_cast<std::size_t>(first - s.base);
                         off + sizeof(T) <= r.off + r.len; off += align) {
                        T cur, prev;
                        std::memcpy(&cur, buf.data() + off, sizeof(T));
                        std::memcpy(&prev, s.data.data() + off, sizeof(T));
                        if (test(c, cur, prev)) {
                            A.push_back(s.base + off);
                            V.insert(V.end(), buf.data() + off, buf.data() + off + sizeof(T));
                        }
                    }
                }
                if (total.fetch_add(A.size()) + A.size() > kMaxCandidates) stop = true;
            });
        });
        std::size_t n = 0;
        for (auto& v : pa) n += v.size();
        if (n > kMaxCandidates)
            throw MemoryError(
                "too many matches (more than 50,000,000 candidates); use a "
                "narrower region filter, a larger alignment, or a more selective "
                "comparison");
        std::vector<Address> addrs;
        std::vector<std::uint8_t> vals;
        addrs.reserve(n);
        vals.reserve(n * sz);
        for (std::size_t i = 0; i < pa.size(); ++i) {
            addrs.insert(addrs.end(), pa[i].begin(), pa[i].end());
            vals.insert(vals.end(), pv[i].begin(), pv[i].end());
        }
        addrs_ = std::move(addrs);
        prev_values_ = std::move(vals);
        snapshots_.clear();
        snapshots_.shrink_to_fit();
        return addrs_.size();
    }

    const std::size_t n = addrs_.size();
    with_type(type_, is64, [&](auto tag) {
        using T = decltype(tag)::type;
        Cmp<T> c = make_cmp<T>(op, value, value2);
        std::vector<std::uint8_t> buf;
        std::size_t out = 0, i = 0;
        while (i < n) {
            Address ws = addrs_[i];
            Address we = ws + sz;
            std::size_t j = i;
            while (j + 1 < n && addrs_[j + 1] + sz - ws <= kChunk && addrs_[j + 1] <= we + 2048) {
                ++j;
                we = addrs_[j] + sz;
            }
            auto len = static_cast<std::size_t>(we - ws);
            if (buf.size() < len) buf.resize(len);
            bool whole = proc.read_partial(ws, buf.data(), len) == len;
            for (std::size_t k = i; k <= j; ++k) {
                Address a = addrs_[k];
                T cur, prev;
                if (whole) {
                    std::memcpy(&cur, buf.data() + (a - ws), sizeof(T));
                } else if (!proc.try_read(a, &cur, sizeof(T))) {
                    continue;  // unreadable -> dropped
                }
                std::memcpy(&prev, prev_values_.data() + k * sizeof(T), sizeof(T));
                if (test(c, cur, prev)) {
                    addrs_[out] = a;
                    std::memcpy(prev_values_.data() + out * sizeof(T), &cur, sizeof(T));
                    ++out;
                }
            }
            i = j + 1;
        }
        addrs_.resize(out);
        prev_values_.resize(out * sizeof(T));
    });
    return addrs_.size();
}

std::vector<ScanHit> ValueScanner::results(std::size_t offset, std::size_t limit) const
{
    std::vector<ScanHit> hits;
    if (!has_scan_ || limit == 0) return hits;
    const Process& proc = *proc_;
    const bool is64 = proc.is_64bit();
    const std::size_t sz = value_size(type_, is64);
    std::vector<std::uint8_t> cur(sz);

    auto emit = [&](Address a, const std::uint8_t* prev) {
        ScanHit h;
        h.address = a;
        h.previous = decode_value(prev, type_, is64);
        if (!proc.try_read(a, cur.data(), sz)) std::ranges::fill(cur, 0);
        h.current = decode_value(cur.data(), type_, is64);
        hits.push_back(h);
    };

    if (!snapshots_.empty()) {
        std::size_t skip = offset;
        for (const auto& s : snapshots_) {
            std::size_t cnt = slot_count(s.base, s.data.size(), alignment_, sz);
            if (skip >= cnt) {
                skip -= cnt;
                continue;
            }
            Address first = round_up(s.base, alignment_);
            for (std::size_t k = skip; k < cnt; ++k) {
                Address a = first + k * alignment_;
                emit(a, s.data.data() + (a - s.base));
                if (hits.size() >= limit) return hits;
            }
            skip = 0;
        }
        return hits;
    }
    for (std::size_t i = offset; i < addrs_.size() && hits.size() < limit; ++i)
        emit(addrs_[i], prev_values_.data() + i * sz);
    return hits;
}

// ---------------------------------------------------------------------------------------------
// Patterns and strings
// ---------------------------------------------------------------------------------------------

BytePattern BytePattern::parse(std::string_view aob)
{
    BytePattern p;
    std::vector<int> nib;  // -1 = wildcard nibble
    // Tokenize: whitespace separates tokens; within a token consume nibble pairs.
    std::size_t i = 0;
    auto bad = [&](const std::string& why) -> MemoryError {
        return MemoryError("invalid byte pattern '" + std::string(aob) + "': " + why);
    };
    while (i < aob.size()) {
        if (std::isspace(static_cast<unsigned char>(aob[i]))) {
            ++i;
            continue;
        }
        std::size_t j = i;
        while (j < aob.size() && !std::isspace(static_cast<unsigned char>(aob[j]))) ++j;
        std::string_view tok = aob.substr(i, j - i);
        i = j;
        // Token is a run of hex digits and '?' ; a single '?' is a whole-byte wildcard.
        if (tok == "?") {
            p.bytes.push_back(0);
            p.mask.push_back(false);
            continue;
        }
        if (tok.size() % 2 != 0)
            throw bad("odd number of hex digits in '" + std::string(tok) + "'");
        for (std::size_t k = 0; k < tok.size(); k += 2) {
            char a = tok[k], b = tok[k + 1];
            if (a == '?' && b == '?') {
                p.bytes.push_back(0);
                p.mask.push_back(false);
                continue;
            }
            int ha = hexval(a), hb = hexval(b);
            if (ha < 0 || hb < 0)
                throw bad(std::string("invalid character in '") + std::string(tok.substr(k, 2)) +
                          "' (partial-nibble wildcards are not supported)");
            p.bytes.push_back(static_cast<std::uint8_t>(ha * 16 + hb));
            p.mask.push_back(true);
        }
    }
    if (p.bytes.empty()) throw bad("empty pattern");
    bool any = false;
    for (bool m : p.mask) any |= m;
    if (!any) throw bad("pattern must contain at least one non-wildcard byte");
    return p;
}

std::vector<Address> scan_pattern(const Process& proc, const BytePattern& pattern,
                                  const RegionFilter& filter, std::size_t max_results)
{
    if (pattern.bytes.empty() || pattern.bytes.size() != pattern.mask.size())
        throw MemoryError("invalid byte pattern");
    Matcher m;
    m.bytes = pattern.bytes;
    m.flags.resize(m.bytes.size());
    for (std::size_t i = 0; i < m.bytes.size(); ++i) m.flags[i] = pattern.mask[i] ? 1 : 0;
    m.finish();
    return run_matcher(proc, m, filter, max_results);
}

namespace {

// UTF-8 -> UTF-16LE bytes. Throws on malformed input.
std::vector<std::uint8_t> utf8_to_utf16le(std::string_view s)
{
    std::vector<std::uint8_t> out;
    auto put = [&](std::uint32_t u) {
        out.push_back(static_cast<std::uint8_t>(u & 0xFF));
        out.push_back(static_cast<std::uint8_t>(u >> 8));
    };
    std::size_t i = 0;
    while (i < s.size()) {
        auto c = static_cast<unsigned char>(s[i]);
        std::uint32_t cp = 0;
        std::size_t extra = 0;
        if (c < 0x80) {
            cp = c;
            extra = 0;
        } else if ((c & 0xE0) == 0xC0) {
            cp = c & 0x1F;
            extra = 1;
        } else if ((c & 0xF0) == 0xE0) {
            cp = c & 0x0F;
            extra = 2;
        } else if ((c & 0xF8) == 0xF0) {
            cp = c & 0x07;
            extra = 3;
        } else
            throw MemoryError("search text is not valid UTF-8");
        for (std::size_t k = 1; k <= extra; ++k) {
            if (i + k >= s.size()) throw MemoryError("search text is not valid UTF-8");
            auto cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0) != 0x80) throw MemoryError("search text is not valid UTF-8");
            cp = (cp << 6) | (cc & 0x3F);
        }
        i += extra + 1;
        if (cp > 0x10FFFF) throw MemoryError("search text is not valid UTF-8");
        if (cp >= 0x10000) {
            cp -= 0x10000;
            put(0xD800 + (cp >> 10));
            put(0xDC00 + (cp & 0x3FF));
        } else {
            put(cp);
        }
    }
    return out;
}

}  // namespace

std::vector<Address> scan_string(const Process& proc, std::string_view utf8_text,
                                 std::string_view encoding, bool case_sensitive,
                                 const RegionFilter& filter, std::size_t max_results)
{
    if (utf8_text.empty()) throw MemoryError("search text is empty");
    std::string enc = lower(encoding);
    Matcher m;
    bool wide = false;
    if (enc == "utf8" || enc == "utf-8") {
        m.bytes.assign(utf8_text.begin(), utf8_text.end());
    } else if (enc == "ascii") {
        for (char ch : utf8_text)
            if (static_cast<unsigned char>(ch) >= 0x80)
                throw MemoryError("text contains non-ASCII characters; use utf8 or utf16 encoding");
        m.bytes.assign(utf8_text.begin(), utf8_text.end());
    } else if (enc == "utf16" || enc == "utf-16" || enc == "utf16le" || enc == "utf-16le") {
        m.bytes = utf8_to_utf16le(utf8_text);
        wide = true;
    } else {
        throw MemoryError("unknown encoding: " + std::string(encoding) +
                          " (expected utf8, utf16 or ascii)");
    }
    m.flags.assign(m.bytes.size(), 1);
    if (!case_sensitive) {
        for (std::size_t i = 0; i < m.bytes.size(); ++i) {
            std::uint8_t b = m.bytes[i];
            bool letter = (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z');
            if (!letter) continue;
            if (wide && (i % 2 != 0)) continue;  // high byte of a code unit
            if (wide && !(i + 1 < m.bytes.size() && m.bytes[i + 1] == 0)) continue;  // not ASCII
            m.flags[i] = 2;
            if (b >= 'A' && b <= 'Z') m.bytes[i] = static_cast<std::uint8_t>(b + 32);
        }
    }
    m.finish();
    return run_matcher(proc, m, filter, max_results);
}

}  // namespace memcore
