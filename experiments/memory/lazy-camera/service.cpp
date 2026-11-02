// Isolated experiment: keep the existing vendor camera implementation and instance.
// Requires the hash-verified Android 10 HIDL headers prepared by the host tool.
#include <android/hardware/camera/provider/2.4/ICameraProvider.h>
#include <binder/ProcessState.h>
#include <cutils/properties.h>
#include <cstring>
#include <type_traits>
#include <unistd.h>
#include "include/hidl/LegacySupport.h"

using android::hardware::LazyServiceRegistrar;
using android::hardware::camera::provider::V2_4::ICameraProvider;

static_assert(std::is_constructible<LazyServiceRegistrar>::value,
              "Use verified Q constructor ABI, not R getInstance ABI");

int main() {
    // Preserve the captured vendor launcher's factory-mode behavior. Its main
    // compares all eight bytes, including NUL, and skips provider registration.
    char bootmode[PROPERTY_VALUE_MAX] = {};
    property_get("ro.bootmode", bootmode, "11");
    if (memcmp(bootmode, "ffbm-01", sizeof("ffbm-01")) == 0 ||
        memcmp(bootmode, "ffbm-02", sizeof("ffbm-02")) == 0) {
        sleep(10);
        return 0;
    }
    android::ProcessState::initWithDriver("/dev/vndbinder");
    return android::hardware::defaultLazyPassthroughServiceImplementation<ICameraProvider>(
        "legacy/0", 6);
}
