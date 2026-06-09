/**
 * @file        system/interfaces/graphics.h
 * @brief       Abstract graphics system interface for dependency injection
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 *              All rights reserved.
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 */

#pragma once

#include <cstdint>
#include <filesystem>

#include <rex/system/xtypes.h>

// Forward declarations
namespace rex::runtime {
class FunctionDispatcher;
}
namespace rex::ui {
class WindowedAppContext;
}
namespace rex::system {
class KernelState;
}

namespace rex::system {

class IGraphicsSystem {
 public:
  virtual ~IGraphicsSystem() = default;
  virtual X_STATUS Setup(runtime::FunctionDispatcher* function_dispatcher,
                         KernelState* kernel_state, ui::WindowedAppContext* app_context,
                         bool with_presentation) = 0;
  virtual void Shutdown() = 0;
  // Initialize the persistent shader/pipeline storage for the title (disk cache so
  // shaders aren't recompiled from scratch every run). Implemented by GraphicsSystem.
  virtual void InitializeShaderStorage(const std::filesystem::path& cache_root,
                                       uint32_t title_id, bool blocking) = 0;
};

}  // namespace rex::system
