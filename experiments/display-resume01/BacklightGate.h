#pragma once
#include <cstdint>
#include <functional>

namespace kaidroid {
// All calls are serialized by the owner. A successful fence belongs to one
// power epoch and must have signaled after that epoch was armed.
class BacklightGate {
public:
    using Writer = std::function<bool(int)>;
    explicit BacklightGate(Writer writer) : write_(writer) {}
    bool power(bool on, int64_t now) {
        ++epoch_;
        on_ = on;
        ready_ = false;
        armedAt_ = now;
        return apply(0, true);
    }
    bool brightness(int level) {
        if (level < 0 || level > 255) return false;
        desired_ = level;
        return apply(on_ && ready_ ? desired_ : 0);
    }
    bool completed(uint64_t epoch, int64_t signalTime) {
        if (!on_ || epoch != epoch_ || signalTime < armedAt_) return false;
        ready_ = true;
        if (apply(desired_)) return true;
        ready_ = false; // retry on a later valid frame after a HAL failure
        return false;
    }
    uint64_t epoch() const { return epoch_; }
    bool needsFrame() const { return on_ && !ready_; }
    int64_t armedAt() const { return armedAt_; }
private:
    bool apply(int level, bool force = false) {
        if (!force && applied_ == level) return true;
        if (!write_(level)) return false;
        applied_ = level;
        return true;
    }
    Writer write_;
    uint64_t epoch_ = 0;
    int64_t armedAt_ = 0;
    bool on_ = false, ready_ = false;
    int desired_ = 0, applied_ = -1;
};
}
