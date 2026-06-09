#pragma once
// [BO-LOAD] Mission-load breakdown probe. Counts + times the work that happens during a level
// load / streaming spike so we can see how much of the "freeze then it plays" is shader/pipeline
// cache-MISS compilation vs. texture streaming. Counters are read-and-reset per frame in
// VulkanCommandProcessor::IssueSwap, which logs a [BO-LOAD] line only while activity is nonzero.
// Cheap atomics; the timed sites (pipeline compile, shader translate) are already expensive ops.
#include <atomic>
#include <chrono>
#include <cstdint>

namespace rex::graphics::bo_load {

extern std::atomic<uint32_t> pipelines_created;      // vkCreateGraphicsPipelines (cache miss)
extern std::atomic<uint64_t> pipeline_compile_ns;    // wall ns inside those creates
extern std::atomic<uint32_t> shaders_translated;     // guest ucode -> SPIR-V translations
extern std::atomic<uint64_t> shader_translate_ns;    // wall ns inside those translations
extern std::atomic<uint32_t> textures_uploaded;      // texture data uploads (streaming)
extern std::atomic<uint64_t> texture_upload_bytes;   // host bytes uploaded for those textures
extern std::atomic<uint64_t> texture_upload_ns;      // CPU wall ns in the upload path
extern std::atomic<uint32_t> tex_inval_gpu;          // texture write-watch fires from GPU writes
extern std::atomic<uint32_t> tex_inval_cpu;          // texture write-watch fires from CPU/guest writes

// [BO-CP] command-processor frame breakdown: is the frame gated by waiting for the guest to
// produce ring commands (guest-CPU-bound) or by executing them (draw/resolve-bound)?
extern std::atomic<uint64_t> cp_wait_ns;             // CP thread spinning/blocked for new ring data
extern std::atomic<uint64_t> cp_exec_ns;             // CP thread inside ExecutePrimaryBuffer
extern std::atomic<uint64_t> cp_texreq_ns;           // CP thread inside RequestTextures (texture sync)
// [BO-DRAW] IssueDraw sub-phase split (all part of cp_exec): which per-draw stage dominates?
extern std::atomic<uint64_t> draw_rt_ns;             // render_target_cache_->Update
extern std::atomic<uint64_t> draw_pipeline_ns;       // ConfigurePipeline (lookup/translate)
extern std::atomic<uint64_t> draw_bindings_ns;       // UpdateBindings (descriptors + uniforms)
extern std::atomic<uint64_t> draw_total_ns;          // whole IssueDraw (cp_exec - this = packet parse)
extern std::atomic<uint64_t> draw_sysconst_ns;       // UpdateSystemConstantValues
extern std::atomic<uint64_t> draw_viewport_ns;       // GetHostViewportInfo + UpdateDynamicState
extern std::atomic<uint64_t> draw_prim_ns;           // primitive_processor_->Process
// Bisecting the previously-UNTIMED IssueDraw "other" (~8ms in heavy scenes): the three biggest
// untimed spans, timed via manual steady_clock (success path only — early-return failures are rare).
extern std::atomic<uint64_t> draw_setup_ns;          // fn top -> loop: shader ucode analysis + draw_util
extern std::atomic<uint64_t> draw_shsamp_ns;         // post-prim -> sampler break: shader xlate + sampler loop
extern std::atomic<uint64_t> draw_record_ns;         // post-bind -> return: vfetch residency + barriers + draw rec
extern std::atomic<uint64_t> draw_drawcmd_ns;        // sub-span of record: SubmitBarriers+EnterRenderPass + vkCmdDraw
extern std::atomic<uint64_t> draw_vkcmd_ns;          // sub-span of drawcmd: just the vkCmd recording (drawcmd-this = SubmitBarriers)
// vertex-fetch residency loop hit-rate: is the ~3ms loop overhead (everything in-sync) or real work?
extern std::atomic<uint32_t> vfetch_seen;            // vfetch indices iterated per frame
extern std::atomic<uint32_t> vfetch_bitsync;         // ... that hit the fast in-sync-bit path (cheapest)
extern std::atomic<uint32_t> vfetch_request;         // ... that called shared_memory_->RequestRange (real streaming)
extern std::atomic<uint64_t> draw_vfetchloop_ns;     // [BO-DRAW4] just the vfetch residency loop (subset of record)
extern std::atomic<uint32_t> reqrange_fast;          // [BO-DRAW4] RequestRange single-range all-valid fast-path hits
extern std::atomic<uint32_t> reqrange_full;          // [BO-DRAW4] RequestRange calls that fell through to RequestRanges

// On-screen debug overlay (F3) snapshot. The command processor publishes a 30-frame-averaged
// view of the [BO-*] metrics here every swap (always on, independent of the BO_PERF log gate);
// the UI's DebugOverlay stats provider reads it. Plain relaxed atomics — no consume, no lock,
// torn-read-tolerant (display only). updates == 0 means "not yet populated".
struct HudSnapshot {
  std::atomic<uint64_t> updates{0};      // bumped each publish (also serves as guest frame count)
  std::atomic<float> frame_ms{0.0f};     // swap-to-swap time (guest frame), 30-frame avg
  std::atomic<float> cp_wait_ms{0.0f};   // CP idle waiting on guest ring (guest-CPU-bound signal)
  std::atomic<float> cp_exec_ms{0.0f};   // CP translating ring -> Vulkan (draw-translation-bound)
  std::atomic<float> await_avg_ms{0.0f}; // GPU fence wait per frame (avg)
  std::atomic<float> await_max_ms{0.0f}; // GPU fence wait recent max (texture-reveal stall spikes)
  std::atomic<float> tex_mb{0.0f};       // texture bytes uploaded per frame (MB), 30-frame avg
  std::atomic<float> tex_count{0.0f};    // textures uploaded per frame, 30-frame avg
  std::atomic<float> inval_gpu{0.0f};    // tex write-watch invalidations from GPU resolves (RT thrash)
  std::atomic<float> inval_cpu{0.0f};    // ... from CPU/guest writes
  std::atomic<float> draws{0.0f};        // draw calls per frame, 30-frame avg
};
extern HudSnapshot g_hud;

// RAII: on scope exit, add elapsed ns to *ns_acc and bump *count. Either may be null.
struct ScopedTally {
  std::atomic<uint32_t>* count;
  std::atomic<uint64_t>* ns_acc;
  std::chrono::steady_clock::time_point t0;
  ScopedTally(std::atomic<uint32_t>* c, std::atomic<uint64_t>* n)
      : count(c), ns_acc(n), t0(std::chrono::steady_clock::now()) {}
  ~ScopedTally() {
    if (ns_acc) {
      auto dt = std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now() - t0)
                    .count();
      ns_acc->fetch_add(uint64_t(dt), std::memory_order_relaxed);
    }
    if (count) count->fetch_add(1, std::memory_order_relaxed);
  }
};

}  // namespace rex::graphics::bo_load
