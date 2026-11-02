#pragma once
#include <cstddef>
#include <string>

// Existing platform-owned directories are configured by kaidroid-data.rc.
// The retained vendor mkdir must not reapply their encryption policy.
static inline bool KaiDroidPreservePlatformDirectoryPolicy(
        const std::string& context, const std::string& path,
        std::size_t argument_count, bool existing_directory) {
#if defined(KAIDROID_ENG_LEGACY_DATA_OWNER)
    return context == "u:r:vendor_init:s0" && existing_directory &&
           argument_count >= 2 && argument_count <= 5 &&
           (path == "/data/fota" || path == "/data/usbmsc" || path == "/data/hostapd");
#else
    (void)context; (void)path; (void)argument_count; (void)existing_directory;
    return false;
#endif
}
