// SPDX-License-Identifier: Apache-2.0
// Explicit HIDL registration compatible with the retained VNDK29 runtime.
// The actual memory accounting remains in the stock Nokia memtrack HAL.
#include <android/hardware/memtrack/1.0/IMemtrack.h>
#include <hidl/HidlTransportSupport.h>

int main() {
    using android::hardware::memtrack::V1_0::IMemtrack;
    android::hardware::configureRpcThreadpool(1, true);
    auto service = IMemtrack::getService("default", true);
    if (service == nullptr) return 1;
    if (service->registerAsService("default") != android::OK) return 2;
    android::hardware::joinRpcThreadpool();
    return 3;
}
