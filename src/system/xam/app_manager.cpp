/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2020 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#include <rex/system/kernel_state.h>
#include <rex/system/xam/app_manager.h>

#include <cstdio>
#include <cstdlib>

namespace rex {
namespace system {
namespace xam {

// [COD4MP-LIVE] Capture every XAM message dispatch (app/message/buffer) so we can see exactly
// what the Live-online (XStorage motd/playlist/settings) stack asks for at signin=2. Release SDK
// suppresses REXKRNL_* logs, so write to stderr directly. Gated on COD4_LIVE_TRACE.
static void live_trace(const char* tag, uint32_t app_id, uint32_t message, uint32_t buffer_ptr,
                       uint32_t buffer_length, X_HRESULT result, memory::Memory* mem) {
  static const bool on = [] {
    const char* v = std::getenv("COD4_LIVE_TRACE");
    return v && v[0] && v[0] != '0';
  }();
  if (!on) return;
  std::fprintf(stderr, "[COD4MP-LIVE] %s app=%08X msg=%08X buf=%08X len=%u -> %08X\n", tag, app_id,
               message, buffer_ptr, buffer_length, (uint32_t)result);
  if (buffer_ptr && buffer_length && buffer_length <= 256 && mem) {
    auto* p = reinterpret_cast<uint8_t*>(mem->TranslateVirtual(buffer_ptr));
    if (p) {
      std::fprintf(stderr, "[COD4MP-LIVE]   buf:");
      for (uint32_t i = 0; i < buffer_length && i < 64; i++) std::fprintf(stderr, " %02X", p[i]);
      std::fprintf(stderr, "\n");
    }
  }
  std::fflush(stderr);
}

App::App(KernelState* kernel_state, uint32_t app_id)
    : kernel_state_(kernel_state), memory_(kernel_state->memory()), app_id_(app_id) {}

void AppManager::RegisterApp(std::unique_ptr<App> app) {
  assert_zero(app_lookup_.count(app->app_id()));
  app_lookup_.insert({app->app_id(), app.get()});
  apps_.push_back(std::move(app));
}

X_HRESULT AppManager::DispatchMessageSync(uint32_t app_id, uint32_t message, uint32_t buffer_ptr,
                                          uint32_t buffer_length) {
  App* app;
  {
    auto it = app_lookup_.find(app_id);
    if (it == app_lookup_.end()) {
      live_trace("sync NOTFOUND", app_id, message, buffer_ptr, buffer_length, X_E_NOTFOUND,
                 apps_.empty() ? nullptr : apps_.front()->memory());
      return X_E_NOTFOUND;
    }
    app = it->second;
  }
  X_HRESULT r = app->DispatchMessageSync(message, buffer_ptr, buffer_length);
  live_trace("sync", app_id, message, buffer_ptr, buffer_length, r, app->memory());
  return r;
}

X_HRESULT AppManager::DispatchMessageAsync(uint32_t app_id, uint32_t message, uint32_t buffer_ptr,
                                           uint32_t buffer_length) {
  App* app;
  {
    auto it = app_lookup_.find(app_id);
    if (it == app_lookup_.end()) {
      live_trace("async NOTFOUND", app_id, message, buffer_ptr, buffer_length, X_E_NOTFOUND,
                 apps_.empty() ? nullptr : apps_.front()->memory());
      return X_E_NOTFOUND;
    }
    app = it->second;
  }
  X_HRESULT r = app->DispatchMessageSync(message, buffer_ptr, buffer_length);
  live_trace("async", app_id, message, buffer_ptr, buffer_length, r, app->memory());
  return r;
}

}  // namespace xam
}  // namespace system
}  // namespace rex
