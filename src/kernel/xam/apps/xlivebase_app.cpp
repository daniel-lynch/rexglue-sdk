/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2021 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#include <rex/kernel/xam/apps/xlivebase_app.h>
#include <rex/logging.h>
#include <rex/thread.h>

namespace rex {
namespace kernel {
namespace xam {
using namespace rex::system;
using namespace rex::system::xam;
namespace apps {
using namespace rex::system;

XLiveBaseApp::XLiveBaseApp(KernelState* kernel_state) : App(kernel_state, 0xFC) {}

// http://mb.mirage.org/bugzilla/xliveless/main.c

X_HRESULT XLiveBaseApp::DispatchMessageSync(uint32_t message, uint32_t buffer_ptr,
                                            uint32_t buffer_length) {
  // NOTE: buffer_length may be zero or valid.
  auto buffer = memory_->TranslateVirtual(buffer_ptr);
  switch (message) {
    case 0x00058004: {
      // Called on startup, seems to just return a bool in the buffer.
      assert_true(!buffer_length || buffer_length == 4);
      REXKRNL_DEBUG("XLiveBaseGetLogonId({:08X})", buffer_ptr);
      memory::store_and_swap<uint32_t>(buffer + 0, 1);  // ?
      return X_E_SUCCESS;
    }
    case 0x00058006: {
      assert_true(!buffer_length || buffer_length == 4);
      REXKRNL_DEBUG("XLiveBaseGetNatType({:08X})", buffer_ptr);
      memory::store_and_swap<uint32_t>(buffer + 0, 1);  // XONLINE_NAT_OPEN
      return X_E_SUCCESS;
    }
    case 0x00058007: {
      // Occurs if title calls XOnlineGetServiceInfo, expects dwServiceId
      // and pServiceInfo. pServiceInfo should contain pointer to
      // XONLINE_SERVICE_INFO structure.
      REXKRNL_DEBUG("CXLiveLogon::GetServiceInfo({:08X}, {:08X})", buffer_ptr, buffer_length);
      return 0x80151802;  // ERROR_CONNECTION_INVALID
    }
    case 0x00058020: {
      // 0x00058004 is called right before this.
      // We should create a XamEnumerate-able empty list here, but I'm not
      // sure of the format.
      // buffer_length seems to be the same ptr sent to 0x00058004.
      REXKRNL_DEBUG("CXLiveFriends::Enumerate({:08X}, {:08X}) unimplemented", buffer_ptr,
                    buffer_length);
      return X_E_FAIL;
    }
    case 0x00058023: {
      REXKRNL_DEBUG(
          "CXLiveMessaging::XMessageGameInviteGetAcceptedInfo({:08X}, {:08X}) "
          "unimplemented",
          buffer_ptr, buffer_length);
      return X_E_FAIL;
    }
    case 0x00058046: {
      // Required to be successful for 4D530910 to detect signed-in profile
      // Doesn't seem to set anything in the given buffer, probably only takes
      // input
      REXKRNL_DEBUG("XLiveBaseUnk58046({:08X}, {:08X}) unimplemented", buffer_ptr, buffer_length);
      return X_E_SUCCESS;
    }
    case 0x0005800E: {
      // [COD4MP-LIVE] Polled in a tight loop by the Find-Match / party matchmaking pump (≈3400×
      // during a single lobby search). Undocumented here; left unimplemented it fell through to the
      // generic FAIL (X_E_FAIL / 0x80004005), which appears to keep the search loop from concluding
      // "0 games found -> host". Treat it as a connection/notify status poll and report
      // success/idle so the matchmaking state machine can advance to the host-fallback path. No
      // known output payload — return success without writing the caller's buffers (mirrors
      // 0x00058046). Gated behind the COD4_LIVE fake overall.
      REXKRNL_DEBUG("XLiveBase 0x0005800E status poll ({:08X}, {:08X}) -> success", buffer_ptr,
                    buffer_length);
      return X_E_SUCCESS;
    }
    case 0x00050009: {
      // [COD4MP-LIVE] CoD4 (IW3) routes its Xbox Live online-storage downloads
      // (motd / playlist / game-settings / stats) through this message via
      // XMsgStartIORequest (see game sub_821094B8 -> XMsgStartIORequest(app=0xFC,
      // msg=0x00050009, overlapped, buf, 40)). The real Live backend is dead, so we
      // report success with no payload: CompleteOverlappedImmediate() then sets the
      // overlapped length to 0, which the game treats as an empty file and falls back
      // to defaults. This clears the otherwise-infinite "Downloading game settings"
      // modal and lets the Xbox Live menu (Barracks / Create-a-Class) settle.
      REXKRNL_DEBUG("CoD4 Live storage download ({:08X}, {:08X}) -> empty success", buffer_ptr,
                    buffer_length);
      return X_E_SUCCESS;
    }
    case 0x00058035: {
      // [COD4MP-LIVE] XStorageBuildServerPath (game sub_8210AC38 -> XMsgInProcessCall).
      // Currently also faked game-side (writes a dummy path + returns 0); handled here
      // too so the path is consistent if the game-side hook is ever removed. Success with
      // the caller's output buffer left as-is (the game only needs a non-error result).
      REXKRNL_DEBUG("CoD4 XStorageBuildServerPath ({:08X}, {:08X}) -> success", buffer_ptr,
                    buffer_length);
      return X_E_SUCCESS;
    }
  }
  REXKRNL_ERROR(
      "Unimplemented XLIVEBASE message app={:08X}, msg={:08X}, arg1={:08X}, "
      "arg2={:08X}",
      app_id(), message, buffer_ptr, buffer_length);
  return X_E_FAIL;
}

}  // namespace apps
}  // namespace xam
}  // namespace kernel
}  // namespace rex
