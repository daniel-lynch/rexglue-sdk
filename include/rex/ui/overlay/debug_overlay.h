/**
 * @file        rex/ui/overlay/debug_overlay.h
 *
 * @brief       ImGui debug overlay dialog for frame timing display.
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 *              All rights reserved.
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 */
#pragma once
#include <rex/ui/imgui_dialog.h>
#include <array>
#include <cstdint>
#include <functional>

namespace rex::ui {

struct FrameStats {
  double frame_time_ms = 0;
  double fps = 0;
  uint64_t frame_count = 0;
  // Extended [BO-*] perf metrics for the overlay (populated by the rexglue stats provider when
  // `extended` is true). All are recent averages; see graphics/bo_load_probe.h HudSnapshot.
  bool extended = false;
  double cp_wait_ms = 0;    // CP idle waiting on guest ring (guest-CPU-bound signal)
  double cp_exec_ms = 0;    // CP translating ring -> Vulkan (draw-translation-bound)
  double await_avg_ms = 0;  // GPU fence wait per frame (avg)
  double await_max_ms = 0;  // GPU fence wait recent max (texture-reveal stall spikes)
  double tex_mb = 0;        // texture MB uploaded per frame (streaming)
  double tex_count = 0;     // textures uploaded per frame
  double inval_gpu = 0;     // texture invalidations from GPU resolves/frame (RT thrash)
  double inval_cpu = 0;     // texture invalidations from CPU/guest writes/frame
  double draws = 0;         // draw calls per frame
};

class DebugOverlayDialog : public ImGuiDialog {
 public:
  using FrameStatsProvider = std::function<FrameStats()>;

  explicit DebugOverlayDialog(ImGuiDrawer* imgui_drawer, FrameStatsProvider stats_provider = {});
  ~DebugOverlayDialog();

  void ToggleVisible() { visible_ = !visible_; }
  bool IsVisible() const { return visible_; }
  void SetStatsProvider(FrameStatsProvider provider) { stats_provider_ = std::move(provider); }

 protected:
  void OnDraw(ImGuiIO& io) override;

 private:
  bool visible_ = false;
  FrameStatsProvider stats_provider_;
#ifdef REXGLUE_ENABLE_PERF_COUNTERS
  static constexpr size_t kFrameHistorySize = 120;
  std::array<float, kFrameHistorySize> frame_time_history_{};
  size_t frame_history_idx_ = 0;
#endif
};

}  // namespace rex::ui
