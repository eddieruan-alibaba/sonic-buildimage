// nhtevent_capi_ut.cpp
//
// Unit tests for NhtEvent C-API (encode / decode).
// Covers plan Task 5-9: encode basic + NULL args, decode basic + error paths, round-trip.

#include <cstdlib>
#include <cstring>
#include <string>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "src/c-api/nhtevent_capi.h"
#include "src/c_nhtevent.h"

// --- Task 5: encode basic ---

TEST(NhtEventCApi, EncodeBasic) {
    char *json_str = nht_event_encode(
        "2064:100::1d/128",
        "2064:100::1d/128", 243,
        "::/0", 0);
    ASSERT_NE(json_str, nullptr);

    auto j = nlohmann::json::parse(json_str);
    EXPECT_EQ(j["rnh_prefix"], "2064:100::1d/128");
    EXPECT_EQ(j["prev_resolved_prefix"], "2064:100::1d/128");
    EXPECT_EQ(j["prev_resolved_nhg_id"], 243u);
    EXPECT_EQ(j["curr_resolved_prefix"], "::/0");
    EXPECT_EQ(j["curr_resolved_nhg_id"], 0u);
    free(json_str);
}

// --- Task 6: encode NULL args ---

TEST(NhtEventCApi, EncodeNullArgReturnsNull) {
    EXPECT_EQ(nht_event_encode(nullptr, "x", 0, "y", 0), nullptr);
    EXPECT_EQ(nht_event_encode("x", nullptr, 0, "y", 0), nullptr);
    EXPECT_EQ(nht_event_encode("x", "y", 0, nullptr, 0), nullptr);
}

// --- Task 7: decode basic ---

TEST(NhtEventCApi, DecodeBasic) {
    const char *js = R"({"rnh_prefix":"2064:200::1e/128",)"
                     R"("prev_resolved_prefix":"2064:200::1e/128",)"
                     R"("prev_resolved_nhg_id":258,)"
                     R"("curr_resolved_prefix":"::/0",)"
                     R"("curr_resolved_nhg_id":0})";
    struct C_NhtEvent out{};
    ASSERT_EQ(nht_event_decode(js, &out), 0);
    EXPECT_STREQ(out.rnh_prefix, "2064:200::1e/128");
    EXPECT_STREQ(out.prev_resolved_prefix, "2064:200::1e/128");
    EXPECT_EQ(out.prev_resolved_nhg_id, 258u);
    EXPECT_STREQ(out.curr_resolved_prefix, "::/0");
    EXPECT_EQ(out.curr_resolved_nhg_id, 0u);
}

// --- Task 8: decode error paths ---

TEST(NhtEventCApi, DecodeInvalidJson) {
    struct C_NhtEvent out{};
    EXPECT_NE(nht_event_decode("not json", &out), 0);
}

TEST(NhtEventCApi, DecodeMissingField) {
    // 缺 curr_resolved_nhg_id
    const char *js = R"({"rnh_prefix":"a","prev_resolved_prefix":"b",)"
                     R"("prev_resolved_nhg_id":1,"curr_resolved_prefix":"c"})";
    struct C_NhtEvent out{};
    EXPECT_NE(nht_event_decode(js, &out), 0);
}

TEST(NhtEventCApi, DecodeNullInputs) {
    struct C_NhtEvent out{};
    EXPECT_NE(nht_event_decode(nullptr, &out), 0);
    EXPECT_NE(nht_event_decode("{}", nullptr), 0);
}

// --- Task 9: round-trip ---

TEST(NhtEventCApi, RoundTripIPv6) {
    char *js = nht_event_encode(
        "2064:200::1e/128",
        "2064:200::1e/128", 258,
        "::/0", 0);
    ASSERT_NE(js, nullptr);

    struct C_NhtEvent out{};
    ASSERT_EQ(nht_event_decode(js, &out), 0);
    EXPECT_STREQ(out.rnh_prefix, "2064:200::1e/128");
    EXPECT_STREQ(out.prev_resolved_prefix, "2064:200::1e/128");
    EXPECT_EQ(out.prev_resolved_nhg_id, 258u);
    EXPECT_STREQ(out.curr_resolved_prefix, "::/0");
    EXPECT_EQ(out.curr_resolved_nhg_id, 0u);
    free(js);
}

TEST(NhtEventCApi, RoundTripIPv4) {
    char *js = nht_event_encode(
        "10.0.0.1/32",
        "10.0.0.1/32", 100,
        "10.0.0.0/24", 200);
    ASSERT_NE(js, nullptr);

    struct C_NhtEvent out{};
    ASSERT_EQ(nht_event_decode(js, &out), 0);
    EXPECT_STREQ(out.rnh_prefix, "10.0.0.1/32");
    EXPECT_STREQ(out.prev_resolved_prefix, "10.0.0.1/32");
    EXPECT_EQ(out.prev_resolved_nhg_id, 100u);
    EXPECT_STREQ(out.curr_resolved_prefix, "10.0.0.0/24");
    EXPECT_EQ(out.curr_resolved_nhg_id, 200u);
    free(js);
}
