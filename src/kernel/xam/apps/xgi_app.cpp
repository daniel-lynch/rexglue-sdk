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

#include <rex/kernel/xam/apps/xgi_app.h>
#include <rex/logging.h>
#include <rex/thread.h>

#include <cstring>

namespace rex {
namespace kernel {
namespace xam {
using namespace rex::system;
using namespace rex::system::xam;
namespace apps {
using namespace rex::system;

XgiApp::XgiApp(KernelState* kernel_state) : App(kernel_state, 0xFB) {}

namespace {
// XSESSION_SEARCHRESULT_HEADER (8 bytes): { uint32 dwSearchResults; uint32 pResults; }.
// The XSession*Search* messages take a caller-allocated results buffer (size in
// results_buffer_size, address in search_results_ptr) and the kernel writes this header at its
// start. Stubbing the search to SUCCESS without writing the header leaves the count undefined, so
// the title never concludes "0 games found" and never falls through to hosting. Writing a
// well-formed EMPTY result set (count = 0, pointer = 0) lets the matchmaking flow proceed to the
// host-fallback path. For a single box + bots, hosting is exactly what we want.
void WriteEmptySearchResults(memory::Memory* mem, uint32_t search_results_ptr,
                             uint32_t results_buffer_size) {
  if (!search_results_ptr || results_buffer_size < 8) {
    // No output buffer yet (e.g. the title's size-probe pass) — nothing to write.
    return;
  }
  uint8_t* results = mem->TranslateVirtual(search_results_ptr);
  memory::store_and_swap<uint32_t>(results + 0, 0);  // dwSearchResults = 0
  memory::store_and_swap<uint32_t>(results + 4, 0);  // pResults = nullptr
}
}  // namespace

// http://mb.mirage.org/bugzilla/xliveless/main.c

X_HRESULT XgiApp::DispatchMessageSync(uint32_t message, uint32_t buffer_ptr,
                                      uint32_t buffer_length) {
  // NOTE: buffer_length may be zero or valid.
  auto buffer = memory_->TranslateVirtual(buffer_ptr);
  switch (message) {
    case 0x000B0006: {
      assert_true(!buffer_length || buffer_length == 24);
      // dword r3 user index
      // dword (unwritten?)
      // qword 0
      // dword r4 context enum
      // dword r5 value
      uint32_t user_index = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t context_id = memory::load_and_swap<uint32_t>(buffer + 16);
      uint32_t context_value = memory::load_and_swap<uint32_t>(buffer + 20);
      REXKRNL_DEBUG("XGIUserSetContextEx({:08X}, {:08X}, {:08X})", user_index, context_id,
                    context_value);
      return X_E_SUCCESS;
    }
    case 0x000B0007: {
      uint32_t user_index = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t property_id = memory::load_and_swap<uint32_t>(buffer + 16);
      uint32_t value_size = memory::load_and_swap<uint32_t>(buffer + 20);
      uint32_t value_ptr = memory::load_and_swap<uint32_t>(buffer + 24);
      REXKRNL_DEBUG("XGIUserSetPropertyEx({:08X}, {:08X}, {}, {:08X})", user_index, property_id,
                    value_size, value_ptr);
      return X_E_SUCCESS;
    }
    case 0x000B0008: {
      assert_true(!buffer_length || buffer_length == 8);
      uint32_t achievement_count = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t achievements_ptr = memory::load_and_swap<uint32_t>(buffer + 4);
      REXKRNL_DEBUG("XGIUserWriteAchievements({:08X}, {:08X})", achievement_count,
                    achievements_ptr);
      return X_E_SUCCESS;
    }
    case 0x000B0010: {
      assert_true(!buffer_length || buffer_length == 28);
      // Sequence:
      // - XamSessionCreateHandle
      // - XamSessionRefObjByHandle
      // - [this]
      // - CloseHandle
      uint32_t session_ptr = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t flags = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t num_slots_public = memory::load_and_swap<uint32_t>(buffer + 8);
      uint32_t num_slots_private = memory::load_and_swap<uint32_t>(buffer + 12);
      uint32_t user_xuid = memory::load_and_swap<uint32_t>(buffer + 16);
      uint32_t session_info_ptr = memory::load_and_swap<uint32_t>(buffer + 20);
      uint32_t nonce_ptr = memory::load_and_swap<uint32_t>(buffer + 24);

      REXKRNL_DEBUG(
          "XGISessionCreateImpl({:08X}, {:08X}, {}, {}, {:08X}, {:08X}, "
          "{:08X})",
          session_ptr, flags, num_slots_public, num_slots_private, user_xuid, session_info_ptr,
          nonce_ptr);

      // [COD4MP-LIVE] Fill a deterministic, self-consistent XSESSION_INFO + nonce so the host
      // session the title creates (e.g. CoD4's Find-Match host-fallback, also Private Match) is
      // usable. Stubbing this to SUCCESS without writing the output left sessionID/nonce zeroed, so
      // the title treated the session as invalid and immediately XSessionDelete'd it, dropping back
      // to "Searching". For a single box + System-Link bots the host XNADDR only needs to be
      // self-consistent (no real online routing). XSESSION_INFO (60B): XNKID sessionID @+0 (8),
      // XNADDR hostAddress @+8 (36: ina@+8, inaOnline@+12, wPortOnline@+16, abEnet@+18, abOnline@+24),
      // XNKEY keyExchangeKey @+44 (16).
      if (session_info_ptr) {
        uint8_t* si = memory_->TranslateVirtual(session_info_ptr);
        std::memset(si, 0, 60);
        static const uint8_t kSessionId[8] = {0x09, 0x04, 0x15, 0x60, 0x7E, 0x00, 0x00, 0x01};
        std::memcpy(si + 0, kSessionId, 8);                 // XNKID (nonzero)
        si[8] = 127; si[9] = 0; si[10] = 0; si[11] = 1;     // ina = 127.0.0.1
        si[12] = 127; si[13] = 0; si[14] = 0; si[15] = 1;   // inaOnline = 127.0.0.1
        static const uint8_t kMac[6] = {0x00, 0x15, 0x5D, 0x00, 0x00, 0x01};
        std::memcpy(si + 18, kMac, 6);                      // abEnet (nonzero MAC)
        si[24] = 0x01;                                      // abOnline (nonzero)
        for (int i = 0; i < 16; i++) si[44 + i] = static_cast<uint8_t>(0xA0 + i);  // XNKEY (nonzero)
      }
      if (nonce_ptr) {
        static const uint8_t kNonce[8] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
        std::memcpy(memory_->TranslateVirtual(nonce_ptr), kNonce, 8);
      }
      return X_E_SUCCESS;
    }
    case 0x000B0011: {
      assert_true(!buffer_length || buffer_length == 16);

      uint32_t obj_ptr = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t flags = memory::load_and_swap<uint32_t>(buffer + 4);
      uint64_t session_nonce = memory::load_and_swap<uint64_t>(buffer + 8);

      REXKRNL_DEBUG("XGISessionDelete({:08X}, {:08X}, {:016X})", obj_ptr, flags, session_nonce);

      return X_E_SUCCESS;
    }
    case 0x000B0012: {
      assert_true(!buffer_length || buffer_length == 20);
      uint32_t session_ptr = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t user_count = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t unk_0 = memory::load_and_swap<uint32_t>(buffer + 8);
      uint32_t user_index_array = memory::load_and_swap<uint32_t>(buffer + 12);
      uint32_t private_slots_array = memory::load_and_swap<uint32_t>(buffer + 16);

      assert_zero(unk_0);
      REXKRNL_DEBUG("XGISessionJoinLocal({:08X}, {}, {}, {:08X}, {:08X})", session_ptr, user_count,
                    unk_0, user_index_array, private_slots_array);
      return X_E_SUCCESS;
    }
    case 0x000B0013: {
      // [COD4MP-LIVE] XGISessionJoinRemote — registers remote (xuid) players into the session. The
      // title calls this right after XSessionCreate on the host path; left unimplemented it fell
      // through to the generic FAIL (0x80004005), so the host aborted and XSessionDelete'd the brand
      // new session, dropping back to "Searching". Report success (no real remote peers on a single
      // box + System-Link bots).
      uint32_t session_ptr = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t user_count = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t xuid_array = memory::load_and_swap<uint32_t>(buffer + 8);
      uint32_t private_slots_array = memory::load_and_swap<uint32_t>(buffer + 12);
      REXKRNL_DEBUG("XGISessionJoinRemote({:08X}, {}, {:08X}, {:08X})", session_ptr, user_count,
                    xuid_array, private_slots_array);
      return X_E_SUCCESS;
    }
    case 0x000B0014: {
      assert_true(!buffer_length || buffer_length == 16);

      uint32_t obj_ptr = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t flags = memory::load_and_swap<uint32_t>(buffer + 4);
      uint64_t session_nonce = memory::load_and_swap<uint64_t>(buffer + 8);

      REXKRNL_DEBUG("XSessionStart({:08X}, {:08X}, {:016X})", obj_ptr, flags, session_nonce);

      return X_STATUS_SUCCESS;
    }
    case 0x000B0015: {
      // send high scores?
      assert_true(!buffer_length || buffer_length == 16);

      uint32_t obj_ptr = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t flags = memory::load_and_swap<uint32_t>(buffer + 4);
      uint64_t session_nonce = memory::load_and_swap<uint64_t>(buffer + 8);

      REXKRNL_DEBUG("XSessionEnd({:08X}, {:08X}, {:016X})", obj_ptr, flags, session_nonce);

      return X_E_SUCCESS;
    }
    case 0x000B0016: {
      assert_true(!buffer_length || buffer_length == 32);

      uint32_t proc_index = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t user_index = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t num_results = memory::load_and_swap<uint32_t>(buffer + 8);
      uint16_t num_props = memory::load_and_swap<uint16_t>(buffer + 12);
      uint16_t num_ctx = memory::load_and_swap<uint16_t>(buffer + 14);
      uint32_t props_ptr = memory::load_and_swap<uint32_t>(buffer + 16);
      uint32_t ctx_ptr = memory::load_and_swap<uint32_t>(buffer + 20);
      uint32_t results_buffer_size = memory::load_and_swap<uint32_t>(buffer + 24);
      uint32_t search_results_ptr = memory::load_and_swap<uint32_t>(buffer + 28);

      REXKRNL_DEBUG("XSessionSearch({}, {}, {}, {}, {}, {:08X}, {:08X}, {}, {:08X})", proc_index,
                    user_index, num_results, num_props, num_ctx, props_ptr, ctx_ptr,
                    results_buffer_size, search_results_ptr);
      WriteEmptySearchResults(memory_, search_results_ptr, results_buffer_size);
      return X_E_SUCCESS;
    }
    case 0x000B0018: {
      assert_true(!buffer_length || buffer_length == 16);

      uint32_t obj_ptr = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t flags = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t maxPublicSlots = memory::load_and_swap<uint32_t>(buffer + 8);
      uint16_t maxPrivateSlots = memory::load_and_swap<uint16_t>(buffer + 12);

      REXKRNL_DEBUG("XSessionModify({:08X}, {:08X}, {:08X}, {:08X})", obj_ptr, flags,
                    maxPublicSlots, maxPrivateSlots);

      return X_E_SUCCESS;
    }
    case 0x000B001C: {
      assert_true(!buffer_length || buffer_length == 36);

      // session_search
      uint32_t proc_index = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t user_index = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t num_results = memory::load_and_swap<uint32_t>(buffer + 8);
      uint16_t num_props = memory::load_and_swap<uint16_t>(buffer + 12);
      uint16_t num_ctx = memory::load_and_swap<uint16_t>(buffer + 14);
      uint32_t props_ptr = memory::load_and_swap<uint32_t>(buffer + 16);
      uint32_t ctx_ptr = memory::load_and_swap<uint32_t>(buffer + 20);
      uint32_t results_buffer_size = memory::load_and_swap<uint32_t>(buffer + 24);
      uint32_t search_results_ptr = memory::load_and_swap<uint32_t>(buffer + 28);
      //
      uint32_t num_users = memory::load_and_swap<uint32_t>(buffer + 32);

      REXKRNL_DEBUG("XSessionSearchEx({}, {}, {}, {}, {}, {:08X}, {:08X}, {}, {:08X}, {})",
                    proc_index, user_index, num_results, num_props, num_ctx, props_ptr, ctx_ptr,
                    results_buffer_size, search_results_ptr, num_users);

      WriteEmptySearchResults(memory_, search_results_ptr, results_buffer_size);
      return X_E_SUCCESS;
    }
    case 0x000B001D: {
      assert_true(!buffer_length || buffer_length == 24);

      uint32_t obj_ptr = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t details_buffer_size = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t session_details_ptr = memory::load_and_swap<uint32_t>(buffer + 8);
      uint32_t reserved1 = memory::load_and_swap<uint32_t>(buffer + 12);
      uint32_t reserved2 = memory::load_and_swap<uint32_t>(buffer + 16);
      uint32_t reserved3 = memory::load_and_swap<uint32_t>(buffer + 20);

      REXKRNL_DEBUG("XSessionGetDetails({:08X}, {}, {:08X}, {}, {}, {})", obj_ptr,
                    details_buffer_size, session_details_ptr, reserved1, reserved2, reserved3);

      return X_E_SUCCESS;
    }
    case 0x000B001E: {
      assert_true(!buffer_length || buffer_length == 24);

      uint32_t obj_ptr = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t session_info_ptr = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t user_index = memory::load_and_swap<uint32_t>(buffer + 8);
      uint32_t reserved1 = memory::load_and_swap<uint32_t>(buffer + 12);
      uint32_t reserved2 = memory::load_and_swap<uint32_t>(buffer + 16);
      uint32_t reserved3 = memory::load_and_swap<uint32_t>(buffer + 20);

      REXKRNL_DEBUG("XSessionMigrateHost({:08X}, {:08X}, {}, {}, {}, {})", obj_ptr,
                    session_info_ptr, user_index, reserved1, reserved2, reserved3);

      return X_E_SUCCESS;
    }
    case 0x000B0019: {
      assert_true(!buffer_length || buffer_length == 8);

      uint32_t user_index = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t session_info_ptr = memory::load_and_swap<uint32_t>(buffer + 4);

      REXKRNL_DEBUG("XSessionGetInvitationData - unimplemented({}, {:08X})", user_index,
                    session_info_ptr);

      return X_E_SUCCESS;
    }
    case 0x000B001A: {
      assert_true(!buffer_length || buffer_length == 28);

      uint32_t obj_ptr = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t flags = memory::load_and_swap<uint32_t>(buffer + 4);
      uint64_t session_nonce = memory::load_and_swap<uint64_t>(buffer + 8);
      uint32_t session_duration_sec = memory::load_and_swap<uint32_t>(buffer + 16);  // 300
      uint32_t results_buffer_size = memory::load_and_swap<uint32_t>(buffer + 20);
      uint32_t results_ptr = memory::load_and_swap<uint32_t>(buffer + 24);

      REXKRNL_DEBUG("XSessionArbitrationRegister({:08X}, {:08X}, {:016X}, {:08X}, {:08X}, {:08X})",
                    obj_ptr, flags, session_nonce, session_duration_sec, results_buffer_size,
                    results_ptr);

      return X_E_SUCCESS;
    }
    case 0x000B001B: {
      assert_true(!buffer_length || buffer_length == 32);

      uint32_t user_index = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t num_session_ids = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t session_ids_ptr = memory::load_and_swap<uint32_t>(buffer + 8);
      uint32_t results_buffer_size = memory::load_and_swap<uint32_t>(buffer + 12);
      uint32_t search_results_ptr = memory::load_and_swap<uint32_t>(buffer + 16);
      uint32_t reserved1 = memory::load_and_swap<uint32_t>(buffer + 20);
      uint32_t reserved2 = memory::load_and_swap<uint32_t>(buffer + 24);
      uint32_t reserved3 = memory::load_and_swap<uint32_t>(buffer + 28);

      REXKRNL_DEBUG("XSessionSearchByID({}, {:08X}, {:08X}, {:08X}, {:08X}, {}, {}, {})",
                    user_index, num_session_ids, session_ids_ptr, results_buffer_size,
                    search_results_ptr, reserved1, reserved2, reserved3);

      return X_E_SUCCESS;
    }
    case 0x000B001F: {
      assert_true(!buffer_length || buffer_length == 24);

      uint32_t obj_ptr = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t array_count = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t xuid_array_ptr = memory::load_and_swap<uint32_t>(buffer + 8);
      uint32_t reserved1 = memory::load_and_swap<uint32_t>(buffer + 12);
      uint32_t reserved2 = memory::load_and_swap<uint32_t>(buffer + 16);
      uint32_t reserved3 = memory::load_and_swap<uint32_t>(buffer + 20);

      REXKRNL_DEBUG("XSessionModifySkill({:08X}, {}, {:08X}, {}, {}, {})", obj_ptr, array_count,
                    xuid_array_ptr, reserved1, reserved2, reserved3);

      return X_E_SUCCESS;
    }
    case 0x000B0020: {
      assert_true(!buffer_length || buffer_length == 8);

      uint32_t user_index = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t view_id = memory::load_and_swap<uint32_t>(buffer + 4);

      REXKRNL_DEBUG("XUserResetStatsView({:08X}, {})", user_index, view_id);

      return X_E_SUCCESS;
    }
    case 0x000B0021: {
      assert_true(!buffer_length || buffer_length == 28);

      uint32_t title_id = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t xuids_count = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t xuids_ptr = memory::load_and_swap<uint32_t>(buffer + 8);
      uint32_t specs_count = memory::load_and_swap<uint32_t>(buffer + 12);
      uint32_t specs_ptr = memory::load_and_swap<uint32_t>(buffer + 16);
      uint32_t results_size = memory::load_and_swap<uint32_t>(buffer + 20);
      uint32_t results_ptr = memory::load_and_swap<uint32_t>(buffer + 24);

      REXKRNL_DEBUG("XUserReadStats({}, {}, {:08X}, {}, {:08X}, {}, {:08X})", title_id, xuids_count,
                    xuids_ptr, specs_count, specs_ptr, results_size, results_ptr);

      return X_E_SUCCESS;
    }
    case 0x000B0025: {
      assert_true(!buffer_length || buffer_length == 20);

      uint32_t obj_ptr = memory::load_and_swap<uint32_t>(buffer + 0);
      uint64_t xuid = memory::load_and_swap<uint64_t>(buffer + 4);
      uint32_t num_views = memory::load_and_swap<uint32_t>(buffer + 12);
      uint32_t views_ptr = memory::load_and_swap<uint32_t>(buffer + 16);

      REXKRNL_DEBUG("XSessionWriteStats({:08X}, {:016X}, {:08X}, {:08X})", obj_ptr, xuid, num_views,
                    views_ptr);

      return X_E_SUCCESS;
    }
    case 0x000B0026: {
      assert_true(!buffer_length || buffer_length == 20);

      uint32_t obj_ptr = memory::load_and_swap<uint32_t>(buffer + 0);
      uint64_t xuid = memory::load_and_swap<uint64_t>(buffer + 4);
      uint32_t num_views = memory::load_and_swap<uint32_t>(buffer + 12);
      uint32_t views_ptr = memory::load_and_swap<uint32_t>(buffer + 16);

      REXKRNL_DEBUG("XSessionFlushStats({:08X}, {:016X}, {:08X}, {:08X})", obj_ptr, xuid, num_views,
                    views_ptr);

      return X_E_SUCCESS;
    }
    case 0x000B0036: {
      // Called after opening xbox live arcade and clicking on xbox live v5759
      // to 5787 and called after clicking xbox live in the game library from
      // v6683 to v6717
      // Does not get sent a buffer
      REXKRNL_DEBUG("XInvalidateGamerTileCache, unimplemented");
      return X_E_FAIL;
    }
    case 0x000B003D: {
      assert_true(!buffer_length || buffer_length == 16);

      uint32_t user_index = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t AnId_buffer_size = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t AnId_buffer_ptr = memory::load_and_swap<uint32_t>(buffer + 8);
      uint32_t block = memory::load_and_swap<uint32_t>(buffer + 12);

      REXKRNL_DEBUG("XUserGetANID({:08X}, {:08X}, {:08X}, {:08X})", user_index, AnId_buffer_size,
                    AnId_buffer_ptr, block);

      return X_E_SUCCESS;
    }
    case 0x000B0041: {
      assert_true(!buffer_length || buffer_length == 32);
      // 00000000 2789fecc 00000000 00000000 200491e0 00000000 200491f0 20049340
      uint32_t user_index = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t context_ptr = memory::load_and_swap<uint32_t>(buffer + 16);
      auto context = context_ptr ? memory_->TranslateVirtual(context_ptr) : nullptr;
      uint32_t context_id = context ? memory::load_and_swap<uint32_t>(context + 0) : 0;
      REXKRNL_DEBUG("XGIUserGetContext({:08X}, {:08X}, {:08X}))", user_index, context_ptr,
                    context_id);
      uint32_t value = 0;
      if (context) {
        memory::store_and_swap<uint32_t>(context + 4, value);
      }
      return X_E_FAIL;
    }
    case 0x000B0060: {
      assert_true(!buffer_length || buffer_length == 32);

      uint32_t user_index = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t num_session_ids = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t session_ids_ptr = memory::load_and_swap<uint32_t>(buffer + 8);
      uint32_t results_buffer_size = memory::load_and_swap<uint32_t>(buffer + 12);
      uint32_t search_results_ptr = memory::load_and_swap<uint32_t>(buffer + 16);
      uint32_t reserved1 = memory::load_and_swap<uint32_t>(buffer + 20);
      uint32_t reserved2 = memory::load_and_swap<uint32_t>(buffer + 24);
      uint32_t reserved3 = memory::load_and_swap<uint32_t>(buffer + 28);

      REXKRNL_DEBUG("XSessionSearchByIds({:08X}, {:08X}, {:08X}, {:08X}, {:08X}, {}, {}, {})",
                    user_index, num_session_ids, session_ids_ptr, results_buffer_size,
                    search_results_ptr, reserved1, reserved2, reserved3);

      return X_E_SUCCESS;
    }
    case 0x000B0065: {
      assert_true(!buffer_length || buffer_length == 52);

      uint32_t proc_index = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t user_index = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t num_results = memory::load_and_swap<uint32_t>(buffer + 8);
      uint16_t num_weighted_properties = memory::load_and_swap<uint16_t>(buffer + 12);
      uint16_t num_weighted_contexts = memory::load_and_swap<uint16_t>(buffer + 14);
      uint32_t weighted_search_properties_ptr = memory::load_and_swap<uint32_t>(buffer + 16);
      uint32_t weighted_search_contexts_ptr = memory::load_and_swap<uint32_t>(buffer + 20);
      uint16_t num_props = memory::load_and_swap<uint16_t>(buffer + 24);
      uint16_t num_ctx = memory::load_and_swap<uint16_t>(buffer + 26);
      uint32_t non_weighted_search_properties_ptr = memory::load_and_swap<uint32_t>(buffer + 28);
      uint32_t non_weighted_search_contexts_ptr = memory::load_and_swap<uint32_t>(buffer + 32);
      uint32_t results_buffer_size = memory::load_and_swap<uint32_t>(buffer + 36);
      uint32_t search_results_ptr = memory::load_and_swap<uint32_t>(buffer + 40);
      uint32_t num_users = memory::load_and_swap<uint32_t>(buffer + 44);
      uint32_t weighted_search = memory::load_and_swap<uint32_t>(buffer + 48);

      REXKRNL_DEBUG(
          "XSessionSearchWeighted({:08X}, {:08X}, {:08X}, {}, {}, {:08X}, {:08X}, {}, {}, {:08X}, "
          "{:08X}, {:08X}, {:08X}, {:08X}, {:08X})",
          proc_index, user_index, num_results, num_weighted_properties, num_weighted_contexts,
          weighted_search_properties_ptr, weighted_search_contexts_ptr, num_props, num_ctx,
          non_weighted_search_properties_ptr, non_weighted_search_contexts_ptr, results_buffer_size,
          search_results_ptr, num_users, weighted_search);

      WriteEmptySearchResults(memory_, search_results_ptr, results_buffer_size);
      return X_E_SUCCESS;
    }
    case 0x000B0071: {
      REXKRNL_DEBUG("XGI 0x000B0071, unimplemented");
      return X_E_SUCCESS;
    }
  }
  REXKRNL_ERROR(
      "Unimplemented XGI message app={:08X}, msg={:08X}, arg1={:08X}, "
      "arg2={:08X}",
      app_id(), message, buffer_ptr, buffer_length);
  return X_E_FAIL;
}

}  // namespace apps
}  // namespace xam
}  // namespace kernel
}  // namespace rex
