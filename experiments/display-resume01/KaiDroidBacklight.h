#pragma once
#include "BacklightGate.h"
#include <android-base/properties.h>
#include <android/hardware/light/2.0/ILight.h>
#include <ui/Fence.h>
#include <utils/Timers.h>
#include <log/log.h>
#include <cerrno>
#include <cmath>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace android {
// Experimental, opt-in only. Nokia's main display is 0..255. Other displays
// and non-backlight light types keep their existing HAL routing.
class KaiDroidBacklight {
public:
    static KaiDroidBacklight& get() {
        static KaiDroidBacklight instance;
        return instance;
    }
    bool supported() const { return supported_; }
    status_t brightness(float value) {
        if (!std::isfinite(value) || (value < 0.f && value != -1.f) || value > 1.f)
            return BAD_VALUE;
        const int level = value <= 0.f ? 0 : static_cast<int>(std::lround(value * 255.f));
        std::lock_guard<std::mutex> lock(mutex_);
        return gate_.brightness(level) ? NO_ERROR : UNKNOWN_ERROR;
    }
    void power(bool on) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!gate_.power(on, systemTime(SYSTEM_TIME_MONOTONIC)))
            ALOGE("KaiDroid backlight: cannot blank before power transition");
        ALOGI("KaiDroid backlight: armed epoch=%llu on=%d",
              static_cast<unsigned long long>(gate_.epoch()), on);
        pendingEpoch_ = 0;
        job_.clear();
        cv_.notify_one();
    }
    void frame(const sp<Fence>& fence) {
        if (!fence || !fence->isValid()) return; // no guessed completion
        std::lock_guard<std::mutex> lock(mutex_);
        if (!gate_.needsFrame() || pendingEpoch_ == gate_.epoch()) return;
        job_ = fence;
        pendingEpoch_ = gate_.epoch();
        cv_.notify_one();
    }
private:
    KaiDroidBacklight() : gate_([this](int value) { return writeLevel(value); }) {
        const bool trial = base::GetBoolProperty("ro.debuggable", false) &&
                base::GetBoolProperty("debug.kaidroid.frame_backlight", false);
        if (!base::GetBoolProperty("ro.kaidroid.frame_backlight", false) && !trial) return;
        // Preserve Treble ownership: the vendor HAL alone writes vendor sysfs.
        light_ = hardware::light::V2_0::ILight::getService();
        if (!light_) return;
        bool hasBacklight = false;
        auto result = light_->getSupportedTypes([&](const auto& types) {
            for (auto type : types)
                if (type == hardware::light::V2_0::Type::BACKLIGHT) hasBacklight = true;
        });
        if (!result.isOk() || !hasBacklight) return;
        supported_ = true;
        worker_ = std::thread([this] { run(); });
    }
    ~KaiDroidBacklight() {
        { std::lock_guard<std::mutex> lock(mutex_); stop_ = true; cv_.notify_one(); }
        if (worker_.joinable()) worker_.join();
    }
    bool writeLevel(int level) {
        hardware::light::V2_0::LightState state{};
        state.color = 0xff000000u | (static_cast<uint32_t>(level) * 0x010101u);
        state.flashMode = hardware::light::V2_0::Flash::NONE;
        state.brightnessMode = hardware::light::V2_0::Brightness::USER;
        auto result = light_->setLight(hardware::light::V2_0::Type::BACKLIGHT, state);
        const bool ok = result.isOk() && result == hardware::light::V2_0::Status::SUCCESS;
        if (!ok) ALOGE("KaiDroid backlight: vendor Light HAL request failed");
        return ok;
    }
    void run() {
        std::unique_lock<std::mutex> lock(mutex_);
        while (!stop_) {
            cv_.wait(lock, [this] { return stop_ || job_ != nullptr; });
            if (stop_) break;
            sp<Fence> fence = job_;
            const uint64_t epoch = pendingEpoch_;
            job_.clear();
            for (;;) {
                lock.unlock();
                const int result = fence->wait(100); // cancellation polling, not a wake delay
                const int64_t signaled = result == 0 ? fence->getSignalTime() : -1;
                lock.lock();
                if (stop_ || gate_.epoch() != epoch) break;
                if (result == -ETIME || result == -ETIMEDOUT) continue;
                pendingEpoch_ = 0;
                if (result == 0 && signaled >= 0 && signaled != INT64_MAX) {
                    if (!gate_.completed(epoch, signaled))
                        ALOGW("KaiDroid backlight: stale fence or brightness write failure");
                    else
                        ALOGI("KaiDroid backlight: ready epoch=%llu fence_ns=%lld",
                              static_cast<unsigned long long>(epoch),
                              static_cast<long long>(signaled));
                } else {
                    ALOGE("KaiDroid backlight: present fence failed: %d", result);
                }
                break;
            }
        }
    }
    sp<hardware::light::V2_0::ILight> light_;
    bool supported_ = false;
    std::mutex mutex_;
    std::condition_variable cv_;
    kaidroid::BacklightGate gate_;
    sp<Fence> job_;
    uint64_t pendingEpoch_ = 0;
    bool stop_ = false;
    std::thread worker_;
};
}
