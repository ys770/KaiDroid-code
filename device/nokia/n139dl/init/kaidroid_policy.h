// Engineering-only policy selection. This is staged into the dedicated AOSP
// checkout; it is not a generic vendor-policy compatibility mechanism.
#pragma once

#include <openssl/sha.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <string>

static bool KaiDroidPolicyFileMatches(const char* path, const char* expected) {
    std::string contents;
    if (!android::base::ReadFileToString(path, &contents)) {
        LOG(ERROR) << "KaiDroid policy input missing: " << path;
        return false;
    }
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(contents.data()), contents.size(), digest);
    const char hex[] = "0123456789abcdef";
    std::string actual;
    actual.reserve(SHA256_DIGEST_LENGTH * 2);
    for (unsigned char byte : digest) {
        actual.push_back(hex[byte >> 4]);
        actual.push_back(hex[byte & 15]);
    }
    if (actual != expected) {
        LOG(ERROR) << "KaiDroid policy input mismatch: " << path;
        return false;
    }
    return true;
}

static bool KaiDroidEngineeringPolicyMatches() {
    const struct { const char* path; const char* sha; } inputs[] = {
        {"/vendor/etc/selinux/vendor_sepolicy.cil",
         "0bc3789bac840546d4a5dd7e94b76f623596973a1cf91991cc428f14f9476862"},
        {"/vendor/etc/selinux/plat_pub_versioned.cil",
         "a00ddfe8b71b2f4d5c77a491db6c2e0add171f60e896ad18d3e4375c998a1076"},
        {"/system/etc/selinux/kaidroid/vendor_sepolicy.cil",
         "1eb3258c9827cd589365338ef0d3d73ca4fb08375fe981a8b2a665d6f963a59f"},
        {"/system/etc/selinux/kaidroid/plat_pub_versioned.cil",
         "b4998d758fb2fd6cfa9484e81b4eb8a17f7f85d259dcd5dd11d596a77ed6e3cc"},
        {"/system/etc/selinux/kaidroid/29.0.compat.cil",
         "400d07488c97bee746b75497432fae13985c368e192d74370a9ffee117d1f799"},
    };
    for (const auto& input : inputs) {
        if (!KaiDroidPolicyFileMatches(input.path, input.sha)) return false;
    }
    return true;
}
