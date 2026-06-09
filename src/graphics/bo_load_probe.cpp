// [BO-LOAD] Definitions of the mission-load breakdown counters declared in
// rex/graphics/bo_load_probe.h. Kept in their own TU at global scope so they have plain external
// linkage (the consuming files command_processor.cpp / pipeline_cache.cpp / texture_cache.cpp are
// inside namespace rex::graphics::vulkan and can't define rex::graphics::bo_load members).
#include <rex/graphics/bo_load_probe.h>

namespace rex::graphics::bo_load {
std::atomic<uint32_t> pipelines_created{0};
std::atomic<uint64_t> pipeline_compile_ns{0};
std::atomic<uint32_t> shaders_translated{0};
std::atomic<uint64_t> shader_translate_ns{0};
std::atomic<uint32_t> textures_uploaded{0};
std::atomic<uint64_t> texture_upload_bytes{0};
std::atomic<uint64_t> texture_upload_ns{0};
std::atomic<uint32_t> tex_inval_gpu{0};
std::atomic<uint32_t> tex_inval_cpu{0};
std::atomic<uint64_t> cp_wait_ns{0};
std::atomic<uint64_t> cp_exec_ns{0};
std::atomic<uint64_t> cp_texreq_ns{0};
std::atomic<uint64_t> draw_rt_ns{0};
std::atomic<uint64_t> draw_pipeline_ns{0};
std::atomic<uint64_t> draw_bindings_ns{0};
std::atomic<uint64_t> draw_total_ns{0};
std::atomic<uint64_t> draw_sysconst_ns{0};
std::atomic<uint64_t> draw_viewport_ns{0};
std::atomic<uint64_t> draw_prim_ns{0};
std::atomic<uint64_t> draw_setup_ns{0};
std::atomic<uint64_t> draw_shsamp_ns{0};
std::atomic<uint64_t> draw_record_ns{0};
std::atomic<uint64_t> draw_drawcmd_ns{0};
std::atomic<uint64_t> draw_vkcmd_ns{0};
std::atomic<uint32_t> vfetch_seen{0};
std::atomic<uint32_t> vfetch_bitsync{0};
std::atomic<uint32_t> vfetch_request{0};
std::atomic<uint64_t> draw_vfetchloop_ns{0};
std::atomic<uint32_t> reqrange_fast{0};
std::atomic<uint32_t> reqrange_full{0};
HudSnapshot g_hud;
}  // namespace rex::graphics::bo_load
