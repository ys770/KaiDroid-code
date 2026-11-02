#include "../experiments/display-resume01/KaiDroidBacklight.h"
#include <cassert>
#include <iostream>
using namespace android;
namespace mock = android::hardware::light::V2_0;
static int last() {
    std::lock_guard<std::mutex> lock(mock::writesMutex);
    assert(!mock::writes.empty()); return mock::writes.back();
}
static void waitFor(int value) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (last() != value && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    assert(last() == value);
}
int main() {
    auto& gate = KaiDroidBacklight::get();
    assert(gate.supported());
    gate.power(true);
    assert(gate.brightness(1.f) == NO_ERROR);
    auto old = sp<Fence>(new Fence);
    gate.frame(old);
    std::this_thread::sleep_for(std::chrono::milliseconds(130));
    assert(last() == 0); // wait timeout must never illuminate
    gate.power(false);
    old->signal();
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    assert(last() == 0);
    gate.power(true);
    auto stale = sp<Fence>(new Fence); stale->signal(1); gate.frame(stale);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    assert(last() == 0);
    auto current = sp<Fence>(new Fence); gate.frame(current);
    assert(gate.brightness(0.4f) == NO_ERROR);
    current->signal(); waitFor(102);
    for (int i = 0; i < 100; ++i) {
        gate.power(false); gate.power(true);
        auto cancelled = sp<Fence>(new Fence); gate.frame(cancelled);
        gate.power(false); gate.power(true);
        auto replacement = sp<Fence>(new Fence); gate.frame(replacement);
        cancelled->signal();
        assert(last() == 0);
        replacement->signal(); waitFor(102);
    }
    gate.power(false); gate.power(true);
    auto zero = sp<Fence>(new Fence); gate.frame(zero);
    assert(gate.brightness(0.f) == NO_ERROR);
    zero->signal(); std::this_thread::sleep_for(std::chrono::milliseconds(20));
    assert(last() == 0);
    assert(gate.brightness(-2.f) == BAD_VALUE);
    assert(gate.brightness(2.f) == BAD_VALUE);
    assert(gate.brightness(NAN) == BAD_VALUE);
    gate.power(false);
    std::cout << "PASS: production worker, timeout-dark, stale/cancelled fences, latest brightness, 100 concurrent epoch replacements\n";
}
