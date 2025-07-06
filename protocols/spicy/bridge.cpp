#include "bridge.h"
#include <hilti/rt/libhilti.h>
#include <spicy/rt/libspicy.h>
#include <cstring>
#include <cstdlib>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include "parsers/http.h"

static thread_local bool t_thread_ready = false;

static inline void ensure_thread_ready() {
    if (!t_thread_ready) {
        hilti::rt::init();      // idempotent, but must run once per thread
        spicy::rt::init();      // idempotent, but must run once per thread
        t_thread_ready = true;
    }
}

static std::mutex g_mutex;
static bool g_runtime_ready = false;

static char* strdup_safe(const char* s) {
    if (!s) return nullptr;
    size_t n = std::strlen(s) + 1;
    char*  p = static_cast<char*>(std::malloc(n));
    if (p) std::memcpy(p, s, n);
    return p;
}

static ParsedField& ensure_slot(ParsedData* dst, const std::string& name) {
    if (dst->field_count >= dst->capacity) {
        int new_cap = dst->capacity ? dst->capacity * 2 : 16;
        dst->fields = static_cast<ParsedField*>(std::realloc(dst->fields, sizeof(ParsedField) * new_cap));
        dst->capacity = new_cap;
    }
    ParsedField& f = dst->fields[dst->field_count++];
    f.name = strdup_safe(name.c_str());
    return f;
}

static void add_field_str(ParsedData* dst, const std::string& name, const std::string& value) {
    auto& f = ensure_slot(dst, name);
    f.value = strdup_safe(value.c_str());
    f.is_binary = 0;
    f.length = static_cast<int>(value.size());
}

static void add_field_bin(ParsedData* dst, const std::string& name, const uint8_t* data, size_t len) {
    auto& f = ensure_slot(dst, name);
    f.value = static_cast<char*>(std::malloc(len));
    if (!f.value) {
        dst->error_message = strdup_safe("memory allocation failed for binary field");
        return;
    }
    std::memcpy(f.value, data, len);
    f.is_binary = 1;
    f.length = static_cast<int>(len);
}

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

static void dump_value(ParsedData* dst, const std::string& prefix, const hilti::rt::type_info::Value& v) {
    const auto& T = v.type();

    if (T.tag == hilti::rt::TypeInfo::ValueReference) {
        dump_value(dst, prefix, T.value_reference->value(v));
        return;
    }
 
    if (T.tag == hilti::rt::TypeInfo::Vector) {
        size_t idx = 0;
        for (const auto& elem : T.vector->iterate(v)) {
            std::string key = prefix + "[" + std::to_string(idx++) + "]";
            dump_value(dst, key, elem);
        }
        return;
    }
    if (T.tag == hilti::rt::TypeInfo::Set) {
        size_t idx = 0;
        for (const auto& elem : T.set->iterate(v)) {
            std::string key = prefix + "[" + std::to_string(idx++) + "]";
            dump_value(dst, key, elem);
        }
        return;
    }

    if (T.tag == hilti::rt::TypeInfo::Map) {
        auto* mt = hilti::rt::type_info::value::auxType<hilti::rt::type_info::Map>(v);

        for (const auto& [k, val] : mt->iterate(v)) {
            std::string kstr = scalar_to_string(k);
            std::string key  = prefix.empty() ? kstr : prefix + "." + kstr;
            dump_value(dst, key, val);
        }
        return;
    }

    if (T.tag == hilti::rt::TypeInfo::Optional) {
        if (auto inner = T.optional->value(v))
            dump_value(dst, prefix, inner);
        else
            add_field_str(dst, prefix, "<nil>");
        return;
    }

    if (T.tag == hilti::rt::TypeInfo::Struct) {
        for (const auto& [info, field] : T.struct_->iterate(v)) {
            std::string key = prefix.empty() ? info.name : prefix + "." + info.name;
            dump_value(dst, key, field);
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


void spicy_init() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_runtime_ready)
        return;
    
    hilti::rt::init();
    spicy::rt::init();
    g_runtime_ready = true;
}

void spicy_cleanup() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_runtime_ready)
        return;
    
    spicy::rt::done();
    hilti::rt::done();
    g_runtime_ready = false;
}

int spicy_is_initialized() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_runtime_ready ? 1 : 0;
}

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

ParsedData* spicy_parse_generic(const char* parser_name, const unsigned char* data, int length) {
    if (!parser_name || ! data || length <= 0)
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
            dump_value(res, "", unit->value());
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

void spicy_free_parser_list(char** p, int n) {
    if (!p)
        return;
    
    for (int i = 0; i < n; ++i)
        std::free(p[i]);
    std::free(p);
}