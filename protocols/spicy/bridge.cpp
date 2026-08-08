#include "bridge.h"
#include <hilti/rt/libhilti.h>
#include <spicy/rt/libspicy.h>
#include <cstring>
#include <cstdlib>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

// Concrete parser modules are registered through generated Spicy linker code.
// Keep this bridge independent of parser-specific generated headers.
// tracks runtime init per thread
static thread_local bool t_thread_ready = false;

// global mutex for runtime init sync
static std::mutex g_mutex;
static bool g_runtime_ready = false;

// Note: Spicy/HILTI keep thread-local state, so we must call init()
// once on every OS thread that touches the runtime. The worker
// goroutine is pinned with runtime.LockOSThread() on the Go side
// initializes HILTI and Spicy for current thread
static inline void ensure_thread_ready() {
    if (!t_thread_ready) {
        hilti::rt::init();      // idempotent, but must run once per thread
        spicy::rt::init();      // idempotent, but must run once per thread
        t_thread_ready = true;
    }
}

// helper for early bail out if a previous allocation failed
// add_field_*() and dump_value() check this so that, after the first
// OOM, we stop allocating and just walk the data
static inline bool has_error(const ParsedData* d) {
    return d && d->error_message;
}

// safely duplicates C string, handling NULL input
// return NULL on OOM; callers must check
static char* strdup_safe(const char* s) {
    if (!s) return nullptr;
    size_t n = std::strlen(s) + 1;
    char*  p = static_cast<char*>(std::malloc(n));
    if (p) std::memcpy(p, s, n);
    return p;
}

// ensures space in the ParsedData fields array and returns
// reference to the next available field slot
// if realloc failed, sets error_message and returns a static dummy slot
// safe because of single worker thread model
static ParsedField& ensure_slot(ParsedData* dst) {
    if (dst->field_count >= dst->capacity) { // need to grow the array
        const int new_cap = dst->capacity ? dst->capacity * 2 : 16;
        
        // realloc safety check
        void* mem = std::realloc(dst->fields, sizeof(ParsedField) * new_cap);
        if (!mem) { // memory allocation failed
            static ParsedField dummy; // placeholder
            dst->error_message = strdup_safe("out of memory while growing ParsedField slot array");
            return dummy;
        }
        dst->fields = static_cast<ParsedField*>(mem);
        dst->capacity = new_cap;
    }

    ParsedField& f  = dst->fields[dst->field_count++];
    f.name          = nullptr;
    f.value         = nullptr;
    f.is_binary     = 0;
    f.length        = 0;
    return f;
}

// adds a string field to the ParsedData structure
static void add_field_str(ParsedData* dst, const std::string& name, const std::string& value){
    if (has_error(dst)) return;

    auto& f = ensure_slot(dst);
    if (has_error(dst)) return;

    f.name = strdup_safe(name.c_str());
    if (!f.name) {
        dst->error_message = strdup_safe("out of memory duplicating field name");
        --dst->field_count; // revert field count increment
        return;
    }
    f.value = strdup_safe(value.c_str());
    if (!f.value) {
        dst->error_message = strdup_safe("out of memory duplicating field value");
        std::free(f.name);
        --dst->field_count; // revert field count increment
        return;
    }
    f.is_binary = 0;
    f.length = static_cast<int>(value.size());
}

// adds a binary field to the ParsedData structure
static void add_field_bin(ParsedData* dst, const std::string& name, const uint8_t* data, size_t len) {
    if (has_error(dst))
        return;

    if (len == 0) {
        add_field_str(dst, name, "");
        return;
    }

    auto& f = ensure_slot(dst);
    if (has_error(dst))
        return;

    f.name = strdup_safe(name.c_str());
    if (!f.name) {
        dst->error_message = strdup_safe("out of memory duplicating field name");
        --dst->field_count;
        return;
    }

    f.value = static_cast<char*>(std::malloc(len));
    if (!f.value) {
        dst->error_message = strdup_safe("memory allocation failed for binary field");
        std::free(f.name);
        --dst->field_count;
        return;
    }
    std::memcpy(f.value, data, len);
    f.is_binary = 1;
    f.length = static_cast<int>(len);
}

// converts HILTI scalar value to its string representation and handles
// various HILTI type system values properly
static std::string scalar_to_string(const hilti::rt::type_info::Value& v) {
    const auto& T = v.type();

    switch (T.tag) {
    case hilti::rt::TypeInfo::UnsignedInteger_uint64:
    case hilti::rt::TypeInfo::SignedInteger_int64:
    case hilti::rt::TypeInfo::UnsignedInteger_uint32:
    case hilti::rt::TypeInfo::SignedInteger_int32:
    case hilti::rt::TypeInfo::UnsignedInteger_uint16:
    case hilti::rt::TypeInfo::SignedInteger_int16:
    case hilti::rt::TypeInfo::UnsignedInteger_uint8:
    case hilti::rt::TypeInfo::SignedInteger_int8:
    case hilti::rt::TypeInfo::Real:
        return std::to_string(v);
    
    case hilti::rt::TypeInfo::Bool:
        return T.bool_->get(v) ? "true" : "false";
    
    case hilti::rt::TypeInfo::String:
        return T.string->get(v);
    
    case hilti::rt::TypeInfo::Enum:
        return std::to_string(v);

    case hilti::rt::TypeInfo::Bytes: {
        const auto& b = T.bytes->get(v);
        return std::string(reinterpret_cast<const char*>(b.data()), b.size());
    }

    case hilti::rt::TypeInfo::ValueReference:
        return scalar_to_string(T.value_reference->value(v));

    default:
        return "<unprintable>";
    }
}

static constexpr int kMaxDepth = 64; // maximum recursion depth for nested structures (prevents stack bombs)

// Recursively flattens HILTI containers to "foo[3].bar" keys and stops at kMaxDepth
static void dump_value(ParsedData* dst, const std::string& prefix, const hilti::rt::type_info::Value& v, int depth = 0) {
    if (depth > kMaxDepth) {
        add_field_str(dst, prefix, "<depth-limit>");
        return;
    }

    const auto& T = v.type();

    if (T.tag == hilti::rt::TypeInfo::ValueReference) {
        dump_value(dst, prefix, T.value_reference->value(v));
        return;
    }
 
    if (T.tag == hilti::rt::TypeInfo::Vector) {
        size_t idx = 0;
        for (const auto& elem : T.vector->iterate(v)) {
            std::string key = prefix + "[" + std::to_string(idx++) + "]";
            dump_value(dst, key, elem, depth + 1);
        }
        return;
    }
    if (T.tag == hilti::rt::TypeInfo::Set) {
        size_t idx = 0;
        for (const auto& elem : T.set->iterate(v)) {
            std::string key = prefix + "[" + std::to_string(idx++) + "]";
            dump_value(dst, key, elem, depth + 1);
        }
        return;
    }

    if (T.tag == hilti::rt::TypeInfo::Map) {
        auto* mt = hilti::rt::type_info::value::auxType<hilti::rt::type_info::Map>(v);

        for (const auto& [k, val] : mt->iterate(v)) {
            std::string kstr = scalar_to_string(k);
            std::string key  = prefix.empty() ? kstr : prefix + "." + kstr;
            dump_value(dst, key, val, depth + 1);
        }
        return;
    }

    if (T.tag == hilti::rt::TypeInfo::Optional) {
        if (auto inner = T.optional->value(v))
            dump_value(dst, prefix, inner, depth + 1);
        else
            add_field_str(dst, prefix, "<nil>");
        return;
    }

    if (T.tag == hilti::rt::TypeInfo::Struct) {
        for (const auto& [info, field] : T.struct_->iterate(v)) {
            std::string key = prefix.empty() ? info.name : prefix + "." + info.name;
            dump_value(dst, key, field, depth + 1);
        }
        return;
    }

    if (T.tag == hilti::rt::TypeInfo::Bytes) {
        const auto& b = T.bytes->get(v);

        bool printable = true;
        for (auto c : b) {
            if (c < 0x20 || c > 0x7e) { printable = false; break; }
        }

        if (printable && b.size() <= 256) {
            add_field_str(dst, prefix, std::string(reinterpret_cast<const char*>(b.data()), b.size()));
        }
        else {
            add_field_bin(dst, prefix, reinterpret_cast<const uint8_t*>(b.data()), b.size());
        }
        return;
    }

    add_field_str(dst, prefix, scalar_to_string(v));
}

// initializes HILTI and Spicy runtimes globally
void spicy_init() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_runtime_ready)
        return;
    
    hilti::rt::init();
    spicy::rt::init();
    g_runtime_ready = true;
}

// cleans up HILTI and Spicy runtimes globally
void spicy_cleanup() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_runtime_ready)
        return;
    
    spicy::rt::done();
    hilti::rt::done();
    g_runtime_ready = false;
}

// checks if the Spicy runtime is initialized
int spicy_is_initialized() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_runtime_ready ? 1 : 0;
}

// lists all available Spicy parsers and returns their names
char** spicy_list_parsers(int* count) {
    std::lock_guard<std::mutex> lock(g_mutex);
    
    ensure_thread_ready();
    
    if (!g_runtime_ready) {
        if (count) *count = 0;
        return nullptr;
    }
    
    if (!count) return nullptr;
    
    try {
        spicy::rt::Driver drv;
        std::stringstream ss;
        drv.listParsers(ss);
        
        std::vector<std::string> names;
        std::string line;
        while (std::getline(ss, line))
            if (line.find("::") != std::string::npos) names.emplace_back(line);
        
        *count = static_cast<int>(names.size());
        if (*count == 0)
            return nullptr;
        
        char** out = static_cast<char**>(std::malloc(sizeof(char*) * *count));
        for (int i = 0; i < *count; ++i)
            out[i] = strdup_safe(names[i].c_str());
        
        return out;
    }
    catch (const std::exception& e) {
        *count = 0;
        return nullptr;
    }
}

// parses data using a specified Spicy parser and returns the parsed data
// called only from the single locked OS thread in the Go worker
ParsedData* spicy_parse_generic(const char* parser_name, const unsigned char* data, int length) {
    if (!parser_name || !data || length <= 0)
    return nullptr;
    
    auto* res = static_cast<ParsedData*>(std::calloc(1, sizeof(ParsedData)));
    if (!res)
    return nullptr;
    
    res->protocol_name = strdup_safe(parser_name);
    
    std::lock_guard<std::mutex> lock(g_mutex);
    
    ensure_thread_ready();

    if (!g_runtime_ready) {
        res->error_message = strdup_safe("runtime not initialized");
        return res;
    }
    
    try {
        spicy::rt::Driver drv;
        auto parser = drv.lookupParser(parser_name);
        
        if (!parser) {
            res->error_message = strdup_safe("parser not found");
            return res;
        }
        
        std::stringstream in;
        in.write(reinterpret_cast<const char*>(data), length);
        
        auto unit = drv.processInput(**parser, in);
        
        if (unit && unit->value()) {
            dump_value(res, "", unit->value(), 0);
        }
        else {
            res->error_message = strdup_safe("no value returned");
        }
    }
    catch (const std::exception& e) {
        res->error_message = strdup_safe(e.what());
    }
    catch (...) {
        res->error_message = strdup_safe("unknown C++ exception");
    }
    
    return res;
}

// frees the memory allocated for ParsedData and its fields
void spicy_free_parsed_data(ParsedData* d) {
    if (!d)
        return;
    
    for (int i = 0; i < d->field_count; ++i) {
        std::free(d->fields[i].name);
        std::free(d->fields[i].value);
    }
    std::free(d->fields);
    std::free(d->protocol_name);
    std::free(d->error_message);
    std::free(d);
}

// frees the memory allocated for a list of parser names
void spicy_free_parser_list(char** p, int n) {
    if (!p)
        return;
    
    for (int i = 0; i < n; ++i)
        std::free(p[i]);
    std::free(p);
}
