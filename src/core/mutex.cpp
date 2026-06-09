/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2015 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#include <rex/thread/mutex.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <vector>

#include <rex/chrono/clock.h>
#include <rex/logging.h>

namespace rex::thread {

namespace {
// [GLOCK PROF] env-gated (BO_GLOCK_PROF=1) return-address histogram of who acquires the
// global lock. Lock-free open-addressed table of caller addr -> count; dumped + reset by
// PerfDumpCallers(). Off by default (one cheap branch per acquire when off).
struct CallerSlot {
  std::atomic<uintptr_t> addr{0};
  std::atomic<uint64_t> count{0};
};
constexpr int kCallerSlots = 1024;
CallerSlot g_callers[kCallerSlots];
const bool g_glock_prof = std::getenv("BO_GLOCK_PROF") != nullptr;

inline void NoteCaller(uintptr_t ra) {
  uint32_t h = uint32_t((ra >> 4) * 2654435761u) & (kCallerSlots - 1);
  for (int p = 0; p < 24; ++p) {
    uint32_t i = (h + p) & (kCallerSlots - 1);
    uintptr_t cur = g_callers[i].addr.load(std::memory_order_relaxed);
    if (cur == ra) {
      g_callers[i].count.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    if (cur == 0) {
      uintptr_t expected = 0;
      if (g_callers[i].addr.compare_exchange_strong(expected, ra, std::memory_order_relaxed) ||
          g_callers[i].addr.load(std::memory_order_relaxed) == ra) {
        g_callers[i].count.fetch_add(1, std::memory_order_relaxed);
        return;
      }
    }
  }
}
}  // namespace

std::recursive_mutex& global_critical_region::mutex() {
  static std::recursive_mutex global_mutex;
  return global_mutex;
}

namespace {
std::atomic<uint64_t> g_glock_acquires{0};
std::atomic<uint64_t> g_glock_wait_ticks{0};
}  // namespace

// [PERF] Time how long we block acquiring the global lock. For a recursive_mutex a
// re-entrant acquire by the owning thread returns ~immediately (≈0 wait), so wait_ticks
// reflects real cross-thread contention.
std::unique_lock<std::recursive_mutex> global_critical_region::AcquireTimed() {
  int64_t t0 = int64_t(rex::chrono::Clock::QueryHostTickCount());
  std::unique_lock<std::recursive_mutex> lock(mutex());
  int64_t dt = int64_t(rex::chrono::Clock::QueryHostTickCount()) - t0;
  if (dt > 0) {
    g_glock_wait_ticks.fetch_add(uint64_t(dt), std::memory_order_relaxed);
  }
  g_glock_acquires.fetch_add(1, std::memory_order_relaxed);
  if (g_glock_prof) {
    NoteCaller(reinterpret_cast<uintptr_t>(__builtin_return_address(0)));
  }
  return lock;
}

void global_critical_region::PerfDumpCallers() {
  if (!g_glock_prof) {
    return;
  }
  std::vector<std::pair<uint64_t, uintptr_t>> v;
  for (auto& s : g_callers) {
    uint64_t c = s.count.load(std::memory_order_relaxed);
    if (c) {
      v.emplace_back(c, s.addr.load(std::memory_order_relaxed));
    }
  }
  std::sort(v.rbegin(), v.rend());
  REXLOG_WARN("[GLOCK] === top global-lock callers (addr : count since last dump) ===");
  for (size_t i = 0; i < v.size() && i < 25; ++i) {
    REXLOG_WARN("[GLOCK] {:#018x} : {}", v[i].second, v[i].first);
  }
  for (auto& s : g_callers) {
    s.addr.store(0, std::memory_order_relaxed);
    s.count.store(0, std::memory_order_relaxed);
  }
}

uint64_t global_critical_region::PerfAcquires() {
  return g_glock_acquires.exchange(0, std::memory_order_relaxed);
}
uint64_t global_critical_region::PerfWaitTicks() {
  return g_glock_wait_ticks.exchange(0, std::memory_order_relaxed);
}

}  // namespace rex::thread
