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

#include <array>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

// [COD4MP-MMBROKER] this process's game-socket real OS ports (defined in src/system/xsocket.cpp), so
// XSessionCreate can advertise the host's actual loopback port to a joining peer.
namespace rex { namespace system {
extern uint16_t g_host_real_ports[8];
extern int g_host_real_port_count;
}}  // namespace rex::system

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

// ===========================================================================
// [COD4MP-MMBROKER] Cross-instance session registry (matchmaking broker).
//
// The host-fallback path makes every instance host its own empty Live session, so two clients never
// meet: XSessionSearch always returns 0 results. The broker fixes that by having the HOST publish its
// XSESSION_INFO to a shared on-disk registry, and the searching CLIENT read that registry and return
// the host as a real search result — so Find-Match on B discovers A's session and joins it through the
// title's normal Live-join path (XNet secure addressing negotiated by the join, no raw direct connect).
//
// Transport is a directory of one-file-per-host blobs (works for two local instances now; a UDP/LSP
// announce backend for cross-machine VPN is the planned follow-up — same publish/read interface).
// Gated by env COD4_MM_BROKER (off => original WriteEmptySearchResults host-fallback behaviour).
//
// XSESSION_SEARCHRESULT (0x5C): XSESSION_INFO info @0x00 (60), dwOpenPublicSlots @0x3C,
// dwOpenPrivateSlots @0x40, dwFilledPublicSlots @0x44, dwFilledPrivateSlots @0x48, cProperties @0x4C,
// cContexts @0x50, pProperties @0x54, pContexts @0x58.
constexpr uint32_t kSearchResultSize = 0x5C;
constexpr uint32_t kSessionInfoSize = 60;
constexpr uint32_t kBrokerMagic = 0x4D4D4252;  // "MMBR"
constexpr int64_t kBrokerTtlSec = 900;         // entries older than this are ignored / reaped
                                               // (generous: covers the 2nd client's boot gap; only
                                               // guards against a crashed host leaving a stale file)

struct BrokerEntry {
  uint32_t magic;
  uint32_t version;
  int32_t pid;
  int64_t ts;                         // last-published unix time (liveness)
  uint8_t info[kSessionInfoSize];     // XSESSION_INFO exactly as it sits in guest memory (big-endian)
  uint32_t open_public, open_private;
  uint32_t filled_public, filled_private;
};

bool broker_on() {
  const char* v = std::getenv("COD4_MM_BROKER");
  return v && v[0] && v[0] != '0';
}

std::string broker_dir() {
  if (const char* d = std::getenv("COD4_MM_REGISTRY"); d && d[0]) return d;
  return "/tmp/cod4_mp_sessions";
}

std::string broker_own_path() {
  return broker_dir() + "/" + std::to_string((int)getpid()) + ".session";
}

void BrokerTrace(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

void BrokerPublishHost(const uint8_t* guest_session_info, uint32_t open_public,
                       uint32_t open_private, uint32_t filled_public, uint32_t filled_private) {
  std::string dir = broker_dir();
  ::mkdir(dir.c_str(), 0777);
  BrokerEntry e{};
  e.magic = kBrokerMagic;
  e.version = 1;
  e.pid = (int)getpid();
  e.ts = (int64_t)::time(nullptr);
  std::memcpy(e.info, guest_session_info, kSessionInfoSize);
  e.open_public = open_public;
  e.open_private = open_private;
  e.filled_public = filled_public;
  e.filled_private = filled_private;
  std::string path = broker_own_path();
  std::string tmp = path + ".tmp";
  if (FILE* f = std::fopen(tmp.c_str(), "wb")) {
    std::fwrite(&e, sizeof e, 1, f);
    std::fclose(f);
    std::rename(tmp.c_str(), path.c_str());  // atomic swap so a reader never sees a half file
  }
  REXKRNL_DEBUG("[MMBROKER] published host session pid={} open_pub={}", e.pid, open_public);
  BrokerTrace("PUBLISH: open_pub=%u open_priv=%u", open_public, open_private);
}

// NOTE: a single instance creates MULTIPLE sessions over a Find-Match flow (a transient search session
// AND the real host session). Since the registry file is keyed by PID, removing it on ANY XSessionDelete
// wiped the host advertisement when the title tore down its search session right after starting to host
// (observed: host reaches the lobby with open_pub=17, then its file vanishes -> a joiner finds nothing).
// So we DON'T delete on XSessionDelete; the TTL reaps a genuinely-gone host. The latest PUBLISH (the host
// session) is what stays advertised.
void BrokerRemoveHost() { BrokerTrace("REMOVE (no-op; TTL-reaped): %s", broker_own_path().c_str()); }

// Direct file trace (bypasses REXKRNL_DEBUG log-level gating) so the cross-instance flow is observable
// during bring-up. Appends to <registry>/trace.log. Always on when the broker is on; cheap.
void BrokerTrace(const char* fmt, ...) {
  std::string path = broker_dir() + "/trace.log";
  FILE* f = std::fopen(path.c_str(), "a");
  if (!f) return;
  std::fprintf(f, "[pid %d t %ld] ", (int)getpid(), (long)::time(nullptr));
  va_list ap;
  va_start(ap, fmt);
  std::vfprintf(f, fmt, ap);
  va_end(ap);
  std::fputc('\n', f);
  std::fclose(f);
}

// Collect live host sessions published by OTHER instances (skip our own pid + stale entries).
std::vector<BrokerEntry> BrokerReadHosts() {
  std::vector<BrokerEntry> out;
  std::string dir = broker_dir();
  DIR* d = ::opendir(dir.c_str());
  if (!d) return out;
  int32_t self = (int)getpid();
  int64_t now = (int64_t)::time(nullptr);
  while (dirent* de = ::readdir(d)) {
    const char* nm = de->d_name;
    size_t L = std::strlen(nm);
    if (L < 9 || std::strcmp(nm + L - 8, ".session") != 0) continue;
    std::string path = dir + "/" + nm;
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) continue;
    BrokerEntry e{};
    size_t got = std::fread(&e, 1, sizeof e, f);
    std::fclose(f);
    if (got != sizeof e || e.magic != kBrokerMagic) continue;
    if (e.pid == self) continue;                       // never return our own session
    if (now - e.ts > kBrokerTtlSec) {                  // stale (host gone) — reap and skip
      std::remove(path.c_str());
      continue;
    }
    out.push_back(e);
  }
  ::closedir(d);
  return out;
}

// Write the discovered hosts into the title's results buffer as XSESSION_SEARCHRESULTs. Returns true
// if it wrote a (possibly zero-count) well-formed result set; false if there is nothing to advertise
// (caller then falls back to WriteEmptySearchResults / host-fallback).
bool BrokerWriteSearchResults(memory::Memory* mem, uint32_t search_results_ptr,
                              uint32_t results_buffer_size, uint32_t max_results) {
  if (!broker_on()) return false;
  std::vector<BrokerEntry> hosts = BrokerReadHosts();
  BrokerTrace("SEARCH: peer_hosts=%zu results_ptr=%08X buf_size=%u max_results=%u", hosts.size(),
              search_results_ptr, results_buffer_size, max_results);
  if (hosts.empty()) return false;                     // no peer hosting -> let host-fallback run
  if (!search_results_ptr || results_buffer_size < 8) {
    BrokerTrace("SEARCH: deferring (size-probe: ptr=%08X size=%u)", search_results_ptr,
                results_buffer_size);
    return false;                                      // size-probe pass: defer
  }

  uint32_t fit = (results_buffer_size - 8) / kSearchResultSize;
  uint32_t count = (uint32_t)hosts.size();
  if (max_results && count > max_results) count = max_results;
  if (count > fit) count = fit;

  uint8_t* base = mem->TranslateVirtual(search_results_ptr);
  uint32_t array_va = search_results_ptr + 8;          // results array right after the 8-byte header
  memory::store_and_swap<uint32_t>(base + 0, count);   // dwSearchResults
  memory::store_and_swap<uint32_t>(base + 4, count ? array_va : 0);  // pResults

  for (uint32_t i = 0; i < count; i++) {
    uint8_t* r = base + 8 + i * kSearchResultSize;
    std::memcpy(r + 0x00, hosts[i].info, kSessionInfoSize);  // XSESSION_INFO (already big-endian)
    memory::store_and_swap<uint32_t>(r + 0x3C, hosts[i].open_public);
    memory::store_and_swap<uint32_t>(r + 0x40, hosts[i].open_private);
    memory::store_and_swap<uint32_t>(r + 0x44, hosts[i].filled_public);
    memory::store_and_swap<uint32_t>(r + 0x48, hosts[i].filled_private);
    memory::store_and_swap<uint32_t>(r + 0x4C, 0);     // cProperties
    memory::store_and_swap<uint32_t>(r + 0x50, 0);     // cContexts
    memory::store_and_swap<uint32_t>(r + 0x54, 0);     // pProperties
    memory::store_and_swap<uint32_t>(r + 0x58, 0);     // pContexts
  }
  REXKRNL_DEBUG("[MMBROKER] search returned {} host session(s) (fit={}, max={})", count, fit,
                max_results);
  for (uint32_t i = 0; i < count; i++) {
    const uint8_t* in = hosts[i].info;
    uint16_t port = (uint16_t)((in[16] << 8) | in[17]);  // XNADDR wPortOnline
    BrokerTrace("SEARCH: result[%u] xnkid=%02X%02X%02X%02X%02X%02X%02X%02X port=%u", i, in[0], in[1],
                in[2], in[3], in[4], in[5], in[6], in[7], port);
  }
  BrokerTrace("SEARCH: RETURNED %u host session(s) to title (fit=%u)", count, fit);
  return true;
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
        // [COD4MP-MMBROKER] UNIQUE XNKID per host process. Was a shared static constant — so every
        // instance's session had the SAME session ID, and a joining peer's matchmaking treated a
        // discovered host's session as its OWN (never actually joining the remote host, just resolving
        // its own address). Derive a stable-per-process id from pid+time; keep byte0=0x09 (session
        // type bits some titles check). Computed once so this process's session id stays consistent.
        static const std::array<uint8_t, 8> kSessionId = [] {
          std::array<uint8_t, 8> id{};
          uint64_t seed = (static_cast<uint64_t>(getpid()) << 32) ^ static_cast<uint64_t>(::time(nullptr));
          id[0] = 0x09;
          for (int i = 1; i < 8; i++) id[i] = static_cast<uint8_t>((seed >> (8 * (i - 1))) & 0xFF);
          return id;
        }();
        std::memcpy(si + 0, kSessionId.data(), 8);          // XNKID (unique per host process)
        si[8] = 127; si[9] = 0; si[10] = 0; si[11] = 1;     // ina = 127.0.0.1
        si[12] = 127; si[13] = 0; si[14] = 0; si[15] = 1;   // inaOnline = 127.0.0.1
        static const uint8_t kMac[6] = {0x00, 0x15, 0x5D, 0x00, 0x00, 0x01};
        std::memcpy(si + 18, kMac, 6);                      // abEnet (nonzero MAC)
        si[24] = 0x01;                                      // abOnline (nonzero)
        for (int i = 0; i < 16; i++) si[44 + i] = static_cast<uint8_t>(0xA0 + i);  // XNKEY (nonzero)
        // [COD4MP-MMBROKER] stamp the host's REAL game-socket OS port into wPortOnline so a joining
        // peer reaches THIS process's actual loopback socket (the guest's Xbox port is ephemeral-
        // remapped at bind — see xsocket.cpp). Which of the host's sockets is the match/VDP one is
        // selectable via COD4_MM_PORT_IDX (default 0) during bring-up.
        int pidx = 0;
        if (const char* pi = std::getenv("COD4_MM_PORT_IDX")) pidx = std::atoi(pi);
        if (pidx < 0 || pidx >= rex::system::g_host_real_port_count) pidx = 0;
        uint16_t hport = rex::system::g_host_real_port_count > 0
                             ? rex::system::g_host_real_ports[pidx]
                             : 0;
        si[16] = static_cast<uint8_t>((hport >> 8) & 0xFF);  // wPortOnline (big-endian)
        si[17] = static_cast<uint8_t>(hport & 0xFF);
        BrokerTrace(
            "XSessionCreate: OWN xnkid=%02X%02X%02X%02X%02X%02X%02X%02X port idx=%d -> wPortOnline=%u "
            "(of %d sockets)",
            si[0], si[1], si[2], si[3], si[4], si[5], si[6], si[7], pidx, (unsigned)hport,
            rex::system::g_host_real_port_count);
      }
      if (nonce_ptr) {
        static const uint8_t kNonce[8] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
        std::memcpy(memory_->TranslateVirtual(nonce_ptr), kNonce, 8);
      }
      // [COD4MP-MMBROKER] Publish this host session so a searching peer can discover + join it. In
      // this title only the host-fallback path reaches XSessionCreate with a session_info to fill, so
      // a present session_info_ptr is a safe "we are hosting" trigger (don't gate on a guessed host
      // flag bit, which would silently publish nothing if wrong; `flags`=0x{:08X} is logged above).
      if (broker_on() && session_info_ptr) {
        BrokerPublishHost(memory_->TranslateVirtual(session_info_ptr), num_slots_public,
                          num_slots_private, 0, 0);
      }
      return X_E_SUCCESS;
    }
    case 0x000B0011: {
      assert_true(!buffer_length || buffer_length == 16);

      uint32_t obj_ptr = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t flags = memory::load_and_swap<uint32_t>(buffer + 4);
      uint64_t session_nonce = memory::load_and_swap<uint64_t>(buffer + 8);

      REXKRNL_DEBUG("XGISessionDelete({:08X}, {:08X}, {:016X})", obj_ptr, flags, session_nonce);

      if (broker_on()) BrokerRemoveHost();  // [COD4MP-MMBROKER] stop advertising a torn-down session

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
      // [COD4MP-MMBROKER] return discovered peer hosts; else fall back to empty (host-fallback).
      if (!BrokerWriteSearchResults(memory_, search_results_ptr, results_buffer_size, num_results))
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

      // [COD4MP-MMBROKER] return discovered peer hosts; else fall back to empty (host-fallback).
      if (!BrokerWriteSearchResults(memory_, search_results_ptr, results_buffer_size, num_results))
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
