#include "../experiments/display-resume01/BacklightGate.h"
#include <cassert>
#include <vector>
#include <iostream>

int main() {
    std::vector<int> writes;
    bool reject = false;
    kaidroid::BacklightGate gate([&](int x) {
        if (reject) return false;
        writes.push_back(x); return true;
    });
    assert(gate.brightness(102));
    assert(writes == std::vector<int>{0});
    assert(gate.power(true, 100));
    auto first = gate.epoch();
    assert(gate.brightness(180));
    assert(writes.back() == 0);
    assert(!gate.completed(first, 99)); // old signaled fence
    assert(gate.needsFrame());
    assert(gate.completed(first, 110));
    assert(writes.back() == 180); // latest, not the pre-wake request
    assert(gate.brightness(70));
    assert(writes.back() == 70);
    assert(gate.power(false, 120));
    assert(writes.back() == 0);
    assert(!gate.completed(first, 130));
    assert(gate.power(true, 140));
    assert(!gate.completed(first, 150)); // late previous-epoch completion
    assert(gate.brightness(0));
    assert(gate.completed(gate.epoch(), 160));
    assert(writes.back() == 0); // off request cancels pending illumination
    assert(!gate.brightness(-1));
    assert(!gate.brightness(256));
    reject = true;
    assert(!gate.brightness(80));
    reject = false;
    assert(gate.brightness(80)); // failed writes are not cached as success
    assert(writes.back() == 80);
    assert(gate.power(true, 170));
    reject = true;
    assert(!gate.completed(gate.epoch(), 180));
    assert(gate.needsFrame());
    reject = false;
    assert(gate.completed(gate.epoch(), 190));
    assert(!gate.needsFrame());
    for (int i = 0; i < 1000; ++i) {
        assert(gate.power(false, 200 + i * 10));
        auto old = gate.epoch();
        assert(gate.power(true, 201 + i * 10));
        assert(gate.brightness(i % 256));
        assert(!gate.completed(old, 205 + i * 10));
        assert(writes.back() == 0);
        assert(gate.completed(gate.epoch(), 205 + i * 10));
        assert(writes.back() == i % 256);
    }
    std::cout << "PASS: latest brightness, cancellation, stale fences, failed writes, 1000 power cycles\n";
}
