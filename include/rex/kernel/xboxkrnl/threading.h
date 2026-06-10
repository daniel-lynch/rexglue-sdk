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

#pragma once

#include <rex/ppc/context.h>
#include <rex/system/xevent.h>
#include <rex/system/xthread.h>
#include <rex/system/xtypes.h>
#include <rex/types.h>

namespace rex::kernel::xboxkrnl {

uint32_t xeNtSetEvent(uint32_t handle, rex::be<uint32_t>* previous_state_ptr);
uint32_t xeNtClearEvent(uint32_t handle);

uint32_t xeNtWaitForMultipleObjectsEx(uint32_t count, rex::be<uint32_t>* handles,
                                      uint32_t wait_type, uint32_t wait_mode, uint32_t alertable,
                                      uint64_t* timeout_ptr);

uint32_t xeKeWaitForSingleObject(void* object_ptr, uint32_t wait_reason, uint32_t processor_mode,
                                 uint32_t alertable, uint64_t* timeout_ptr);
uint32_t xeKeSetEvent(rex::system::X_KEVENT* event_ptr, uint32_t increment, uint32_t wait);

// Guest-memory spinlock helpers (PPCContext* for r13/PCR access)
uint32_t xeKeKfAcquireSpinLock(PPCContext* ctx, rex::X_KSPINLOCK* lock, bool change_irql = true);
void xeKeKfReleaseSpinLock(PPCContext* ctx, rex::X_KSPINLOCK* lock, uint32_t old_irql,
                           bool change_irql = true);

// Release every guest spinlock the CURRENT host thread holds, rebalancing the global
// critical region and restoring IRQL. Call this immediately before an engine non-local
// exit (idTech-style Com_Error setjmp/longjmp, e.g. BO sub_825FB7A0) transfers control
// back to its setjmp site: the longjmp unwinds the guest stack without running the
// matching KfReleaseSpinLock, which would otherwise leak the recursive global lock and
// leave stale spinlock owner fields -> the next interrupt that takes one of those
// spinlocks spins forever while holding the global lock, deadlocking the emulator.
void xeReleaseHeldSpinLocksForNonLocalExit(PPCContext* ctx);

// Guest-memory APC helpers
void xeKeInitializeApc(rex::system::XAPC* apc, uint32_t thread_ptr, uint32_t kernel_routine,
                       uint32_t rundown_routine, uint32_t normal_routine, uint32_t apc_mode,
                       uint32_t normal_context);
uint32_t xeKeInsertQueueApc(rex::system::XAPC* apc, uint32_t arg1, uint32_t arg2,
                            uint32_t priority_increment, PPCContext* ctx);

}  // namespace rex::kernel::xboxkrnl
