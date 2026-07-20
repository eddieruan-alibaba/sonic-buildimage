// nhtevent_capi.cpp
//
// C-API implementation for NhtEvent JSON encoding/decoding.
// Used by SONiC FPM provider (dplane_fpm_sonic.c) to serialize NHT events
// into RTM_NEWNHTEVENT netlink payloads.

#include "src/nhtevent.h"
#include "src/nhtevent_json.h"
#include "src/c_nhtevent.h"
#include "nhtevent_capi.h"

#include <cstdlib>
#include <cstring>
#include <string>
#include <algorithm>
#include <stdexcept>

extern "C" {

char *nht_event_encode(
    const char *rnh_prefix,
    const char *prev_resolved_prefix,
    uint32_t    prev_resolved_nhg_id,
    const char *curr_resolved_prefix,
    uint32_t    curr_resolved_nhg_id)
{
    if (!rnh_prefix || !prev_resolved_prefix || !curr_resolved_prefix) {
        return nullptr;
    }

    try {
        fib::NhtEvent ev;
        ev.rnh_prefix           = rnh_prefix;
        ev.prev_resolved_prefix = prev_resolved_prefix;
        ev.prev_resolved_nhg_id = prev_resolved_nhg_id;
        ev.curr_resolved_prefix = curr_resolved_prefix;
        ev.curr_resolved_nhg_id = curr_resolved_nhg_id;

        nlohmann::json j = ev;
        std::string s = j.dump();

        char *out = static_cast<char*>(std::malloc(s.size() + 1));
        if (!out) {
            return nullptr;
        }
        std::memcpy(out, s.c_str(), s.size() + 1);
        return out;
    } catch (...) {
        return nullptr;
    }
}

char *nhtevent_json_from_c_nht(const struct C_NhtEvent *c_nht)
{
    if (!c_nht) {
        return nullptr;
    }

    try {
        fib::NhtEvent ev;
        ev.rnh_prefix           = c_nht->rnh_prefix;
        ev.prev_resolved_prefix = c_nht->prev_resolved_prefix;
        ev.prev_resolved_nhg_id = c_nht->prev_resolved_nhg_id;
        ev.curr_resolved_prefix = c_nht->curr_resolved_prefix;
        ev.curr_resolved_nhg_id = c_nht->curr_resolved_nhg_id;

        nlohmann::json j = ev;
        std::string s = j.dump();

        char *out = static_cast<char*>(std::malloc(s.size() + 1));
        if (!out) {
            return nullptr;
        }
        std::memcpy(out, s.c_str(), s.size() + 1);
        return out;
    } catch (...) {
        return nullptr;
    }
}

int nht_event_decode(const char *json_str, struct C_NhtEvent *out)
{
    if (!json_str || !out) {
        return -1;
    }

    try {
        auto j = nlohmann::json::parse(json_str);
        fib::NhtEvent ev = j.get<fib::NhtEvent>();

        auto copy_str = [](char *dst, const std::string &src) {
            size_t n = std::min(src.size(), static_cast<size_t>(C_NHTEVENT_PREFIX_STR_LEN - 1));
            std::memcpy(dst, src.data(), n);
            dst[n] = '\0';
        };

        copy_str(out->rnh_prefix,           ev.rnh_prefix);
        copy_str(out->prev_resolved_prefix, ev.prev_resolved_prefix);
        copy_str(out->curr_resolved_prefix, ev.curr_resolved_prefix);
        out->prev_resolved_nhg_id = ev.prev_resolved_nhg_id;
        out->curr_resolved_nhg_id = ev.curr_resolved_nhg_id;
        return 0;
    } catch (...) {
        return -2;
    }
}

}  // extern "C"
