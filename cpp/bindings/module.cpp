// nanobind bindings for the memcore C++ library -> Python module memory_mcp._memcore.
// Declarations only: adaptation logic lives in memcore::PyApi (py_api.hpp).
#include <cstdint>

#include "py_api.hpp"
#include <nanobind/nanobind.h>
#include <nanobind/stl/optional.h>
#include <nanobind/stl/shared_ptr.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/string_view.h>
#include <nanobind/stl/variant.h>
#include <nanobind/stl/vector.h>

namespace nb = nanobind;
using namespace nb::literals;
namespace mc = memcore;
using mc::PyApi;

NB_MODULE(_memcore, m)
{
    m.doc() = "Read-only Windows process memory access (C++ core).";

    nb::exception<mc::MemoryError> give_me_a_name(m, "MemoryError", PyExc_RuntimeError);

    // ---- enums (Python-facing functions take strings; enums are bound for completeness)
    nb::enum_<mc::ValueType>(m, "ValueType")
        .value("I8", mc::ValueType::I8)
        .value("U8", mc::ValueType::U8)
        .value("I16", mc::ValueType::I16)
        .value("U16", mc::ValueType::U16)
        .value("I32", mc::ValueType::I32)
        .value("U32", mc::ValueType::U32)
        .value("I64", mc::ValueType::I64)
        .value("U64", mc::ValueType::U64)
        .value("F32", mc::ValueType::F32)
        .value("F64", mc::ValueType::F64)
        .value("Ptr", mc::ValueType::Ptr);
    nb::enum_<mc::CompareOp>(m, "CompareOp")
        .value("Exact", mc::CompareOp::Exact)
        .value("Greater", mc::CompareOp::Greater)
        .value("Less", mc::CompareOp::Less)
        .value("Between", mc::CompareOp::Between)
        .value("Changed", mc::CompareOp::Changed)
        .value("Unchanged", mc::CompareOp::Unchanged)
        .value("Increased", mc::CompareOp::Increased)
        .value("Decreased", mc::CompareOp::Decreased)
        .value("Unknown", mc::CompareOp::Unknown);

    m.def("parse_value_type", &mc::parse_value_type, "name"_a);
    m.def("value_type_name", &mc::value_type_name, "type"_a);
    m.def("parse_compare", &mc::parse_compare, "name"_a);
    m.def("value_size", &PyApi::value_size, "type"_a, "is_64bit"_a = true);

    // ---- info structs
    nb::class_<mc::ProcessInfo>(m, "ProcessInfo")
        .def_ro("pid", &mc::ProcessInfo::pid)
        .def_ro("ppid", &mc::ProcessInfo::ppid)
        .def_ro("threads", &mc::ProcessInfo::threads)
        .def_ro("name", &mc::ProcessInfo::name)
        .def_ro("is_64bit", &mc::ProcessInfo::is_64bit)
        .def("__repr__", &PyApi::repr_process_info);

    nb::class_<mc::ModuleInfo>(m, "ModuleInfo")
        .def_ro("name", &mc::ModuleInfo::name)
        .def_ro("path", &mc::ModuleInfo::path)
        .def_ro("base", &mc::ModuleInfo::base)
        .def_ro("size", &mc::ModuleInfo::size)
        .def("__repr__", &PyApi::repr_module_info);

    nb::class_<mc::RegionInfo>(m, "RegionInfo")
        .def_ro("base", &mc::RegionInfo::base)
        .def_ro("size", &mc::RegionInfo::size)
        .def_ro("state", &mc::RegionInfo::state)
        .def_ro("protect", &mc::RegionInfo::protect)
        .def_ro("type", &mc::RegionInfo::type)
        .def_ro("protect_str", &mc::RegionInfo::protect_str)
        .def_ro("type_str", &mc::RegionInfo::type_str)
        .def_ro("module", &mc::RegionInfo::module)
        .def("__repr__", &PyApi::repr_region_info);

    nb::class_<mc::ScanHit>(m, "ScanHit")
        .def_ro("address", &mc::ScanHit::address)
        .def_ro("previous", &mc::ScanHit::previous)
        .def_ro("current", &mc::ScanHit::current)
        .def("__repr__", &PyApi::repr_scan_hit);

    m.def("list_processes", &mc::list_processes, nb::call_guard<nb::gil_scoped_release>());

    // ---- Process
    nb::class_<mc::Process>(m, "Process")
        .def("__init__", &PyApi::init_process, "pid"_a)
        .def_prop_ro("pid", &mc::Process::pid)
        .def_prop_ro("is_64bit", &mc::Process::is_64bit)
        .def("name", &mc::Process::name)
        .def("path", &mc::Process::path)
        .def("is_alive", &mc::Process::is_alive)
        .def("modules", &mc::Process::modules, nb::call_guard<nb::gil_scoped_release>())
        .def("find_module", &mc::Process::find_module, "name"_a,
             nb::call_guard<nb::gil_scoped_release>())
        .def("regions", &PyApi::regions, "readable_only"_a = true, "writable"_a = nb::none(),
             "executable"_a = nb::none(), "type"_a = nb::none(), "module"_a = nb::none(),
             "start"_a = 0, "end"_a = UINT64_MAX)
        .def("read", &PyApi::read, "address"_a, "size"_a)
        .def("read_partial", &PyApi::read_partial, "address"_a, "size"_a)
        .def("resolve", &mc::Process::resolve, "expr"_a);

    // ---- reader
    m.def("read_string", &mc::read_string, "process"_a, "address"_a, "max_len"_a = 256,
          "encoding"_a = "utf8", nb::call_guard<nb::gil_scoped_release>());
    m.def("read_value", &PyApi::read_value, "process"_a, "address"_a, "type"_a);
    m.def("read_values", &PyApi::read_values, "process"_a, "address"_a, "type"_a, "count"_a);
    m.def("decode_value", &PyApi::decode_value, "data"_a, "type"_a, "is_64bit"_a = true);
    m.def("encode_value", &PyApi::encode_value, "value"_a, "type"_a, "is_64bit"_a = true);
    m.def("read_pointer_chain", &mc::read_pointer_chain, "process"_a, "base"_a, "offsets"_a,
          nb::call_guard<nb::gil_scoped_release>());

    // ---- pattern / string scans (return list of addresses)
    m.def("scan_pattern", &PyApi::scan_pattern, "process"_a, "pattern"_a, "readable_only"_a = true,
          "writable"_a = nb::none(), "executable"_a = nb::none(), "type"_a = nb::none(),
          "module"_a = nb::none(), "start"_a = 0, "end"_a = UINT64_MAX, "max_results"_a = 100);
    m.def("scan_string", &PyApi::scan_string, "process"_a, "text"_a, "encoding"_a = "utf8",
          "case_sensitive"_a = true, "readable_only"_a = true, "writable"_a = nb::none(),
          "executable"_a = nb::none(), "type"_a = nb::none(), "module"_a = nb::none(),
          "start"_a = 0, "end"_a = UINT64_MAX, "max_results"_a = 100);

    // ---- ValueScanner
    nb::class_<mc::ValueScanner>(m, "ValueScanner")
        .def("__init__", &PyApi::init_scanner, "process"_a, "type"_a)
        .def("first_scan", &PyApi::first_scan, "compare"_a, "value"_a = nb::none(),
             "value2"_a = nb::none(), "readable_only"_a = true, "writable"_a = nb::none(),
             "executable"_a = nb::none(), "type"_a = nb::none(), "module"_a = nb::none(),
             "start"_a = 0, "end"_a = UINT64_MAX, "alignment"_a = 0)
        .def("next_scan", &PyApi::next_scan, "compare"_a, "value"_a = nb::none(),
             "value2"_a = nb::none())
        .def("count", &mc::ValueScanner::count)
        .def("results", &mc::ValueScanner::results, "offset"_a = 0, "limit"_a = 50,
             nb::call_guard<nb::gil_scoped_release>())
        .def("type", &PyApi::scanner_type);
}
