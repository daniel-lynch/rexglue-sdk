/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2013 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <unistd.h>

#include <rex/kernel/xam/module.h>
#include <rex/platform.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xsocket.h>
// #include <rex/system/xnet.h>

#include <rex/net/socket.h>

// Standard socket types used by Xbox API emulation
#if REX_PLATFORM_WIN32
#include <WinSock2.h>

#include <WS2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#endif

namespace rex::system {

// [COD4MP-MMBROKER] Real OS ports of this process's game sockets (getsockname after Bind), in bind
// order. The matchmaking broker (xgi_app.cpp XSessionCreate) advertises one of these as the host's
// session port so a joining peer can reach the host's actual loopback socket. Which index is the
// match/VDP socket is selectable via COD4_MM_PORT_IDX during bring-up.
uint16_t g_host_real_ports[8] = {0};
int g_host_real_port_count = 0;
// [COD4MP-MMBROKER] The GUEST (Xbox) port that each g_host_real_ports[] entry was bound for, same index.
// The title binds several fixed guest ports (e.g. 59395=lobby/party, 59651=game listen server); each maps
// to a distinct real OS port. Published to the broker so a joiner can route per-guest-port (lobby->lobby,
// game->game) instead of collapsing everything onto one advertised port.
uint16_t g_host_guest_ports[8] = {0};

// [COD4MP-MMBROKER] The joined peer host's guest->real port map (read from the broker on guest-adopt). The
// title sends to the peer at its FIXED guest port (identical across instances); SendTo rewrites to the
// peer's REAL OS port FOR THAT GUEST PORT so a game-connect (guest 59651) reaches the host's game listen
// server (real 48325) instead of being misrouted to the host's lobby socket (the single advertised port).
uint16_t g_peer_map_guest[8] = {0};
uint16_t g_peer_map_real[8] = {0};
int g_peer_map_count = 0;

// guest port -> peer real OS port (0 if unknown)
static uint16_t PeerRealForGuest(uint16_t guest) {
  for (int i = 0; i < g_peer_map_count; i++)
    if (g_peer_map_guest[i] == guest) return g_peer_map_real[i];
  return 0;
}
// peer real OS port -> the guest port the title addressed (0 if unknown) — for the RecvFrom reverse rewrite
static uint16_t PeerGuestForReal(uint16_t real_) {
  for (int i = 0; i < g_peer_map_count; i++)
    if (g_peer_map_real[i] == real_) return g_peer_map_guest[i];
  return 0;
}

// [COD4MP-MMBROKER] The DISCOVERED remote host's XNKID (set when this instance adopts a host as a guest
// in xgi_app XSessionCreate). XnAddrToInAddr returns 127.0.0.2 only for THIS xnkid (the peer) and
// 127.0.0.1 for everything else (self/local) — the title's own session must resolve to 127.0.0.1.
uint8_t g_peer_session_id[8] = {0};
bool g_peer_session_id_set = false;

// [COD4MP-MMBROKER] The joined host peer's REAL OS port (advertised wPortOnline), captured when this
// instance adopts a discovered host (xgi_app guest XSessionCreate). The title sends to the peer's FIXED
// guest port (e.g. 59395) at the peer sentinel IP 127.0.0.x (x!=1); SendTo rewrites that to
// 127.0.0.1:<g_peer_real_port> so packets actually reach the host's loopback socket on the same box.
uint16_t g_peer_real_port = 0;
// [COD4MP-MMBROKER] The guest (Xbox) port the title sends to the peer (e.g. 59395), captured at SendTo.
// RecvFrom rewrites the host's reply source (127.0.0.1:<real port>) back to the sentinel the title
// expects (127.0.0.2:<this guest port>) so the joiner's netchannel accepts the reply (source must match).
uint16_t g_peer_guest_port = 0;

// [COD4MP-MMNETNS] netns mode = each instance runs in its own network namespace on a distinct real veth
// IP (COD4_LOCAL_IP). Then the title's Xbox ports bind for real (no same-box conflict) and peers are
// reached directly at their real IP:port — so the per-port NAT remap + GAMEROUTE reroute (both invented
// to work around the single shared loopback) must be BYPASSED. Detected by COD4_LOCAL_IP being set.
static bool Cod4NetnsMode() {
  static int on = [] {
    const char* s = std::getenv("COD4_LOCAL_IP");
    return (s && s[0]) ? 1 : 0;
  }();
  return on != 0;
}

// [COD4MP-MMNOREROUTE] Disable the netns 59395<->59651 game-port reroute. With COD4_MM_PORT_IDX=2 the host
// advertises its GAME socket (59651) as wPortOnline, so the joiner connects DIRECTLY to the game server and
// the connect + gamestate live on ONE socket (real single-connection) — then the reroute must be off or it
// mis-presents the gamestate source vs where the netchannel connected.
static bool Cod4NoReroute() {
  static int on = [] {
    const char* s = std::getenv("COD4_MM_NOREROUTE");
    return (s && s[0] && s[0] != '0') ? 1 : 0;
  }();
  return on != 0;
}

// [COD4MP-MMBROKER] Budgeted datagram tracer — log where this process actually sends/receives game
// packets so we can see whether a joining peer ever attempts a netchannel connect to the host (and on
// which port) vs being blocked upstream in the matchmaking SM. Bounded so a live match doesn't flood.
// Toggle/scope via COD4_MM_REGISTRY (writes <registry>/nettrace.log alongside BIND/XnAddr traces).
static void NetPktTrace(const char* dir, uint32_t be_ip, uint16_t be_port, int len,
                        const uint8_t* payload = nullptr) {
  static int budget = []{ const char* b = std::getenv("COD4_MM_NETLOG_BUDGET");
                          return (b && b[0]) ? std::atoi(b) : 400; }();
  // [COD4MP-MMBROKER] COD4_MM_NETLOG_DUMP=1 also dumps the first bytes of each datagram — the decisive
  // migration probe: reveals the IW3 connectionless command (0xFFFFFFFF + ascii) or netchannel seq that
  // host A sends the joiner at match-start (the "packets B ACKs but doesn't act on").
  static int dump = []{ const char* d = std::getenv("COD4_MM_NETLOG_DUMP");
                        return (d && d[0]) ? std::atoi(d) : 0; }();
  if (budget <= 0) return;
  --budget;
  const char* d = std::getenv("COD4_MM_REGISTRY");
  std::string path = std::string(d && d[0] ? d : "/tmp/cod4_mp_sessions") + "/nettrace.log";
  if (FILE* f = std::fopen(path.c_str(), "a")) {
    const uint8_t* b = reinterpret_cast<const uint8_t*>(&be_ip);  // s_addr bytes are already net order
    std::fprintf(f, "[pid %d] PKT %s %u.%u.%u.%u:%u len=%d", (int)getpid(), dir,
                 b[0], b[1], b[2], b[3], (unsigned)ntohs(be_port), len);
    if (dump && payload && len > 0) {
      int n = len < 64 ? len : 64;
      std::fprintf(f, " hex=");
      for (int i = 0; i < (n < 16 ? n : 16); i++) std::fprintf(f, "%02x", payload[i]);
      std::fprintf(f, " ascii='");
      for (int i = 0; i < n; i++) {
        uint8_t c = payload[i];
        std::fputc((c >= 0x20 && c < 0x7F) ? c : '.', f);
      }
      std::fputc('\'', f);
    }
    std::fputc('\n', f);
    std::fclose(f);
  }
}

XSocket::XSocket(KernelState* kernel_state) : XObject(kernel_state, kObjectType) {}

XSocket::XSocket(KernelState* kernel_state, uint64_t native_handle)
    : XObject(kernel_state, kObjectType), native_handle_(native_handle) {}

XSocket::~XSocket() {
  Close();
}

X_STATUS XSocket::Initialize(AddressFamily af, Type type, Protocol proto) {
  af_ = af;
  type_ = type;
  proto_ = proto;

  if (proto == Protocol::IPPROTO_VDP) {
    // VDP is a layer on top of UDP.
    proto = Protocol::IPPROTO_UDP;
  }

  native_handle_ = socket(af, type, proto);
  if (native_handle_ == -1) {
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::Close() {
  int ret = rex::net::socket_close(native_handle_);
  if (ret != 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::SetOption(uint32_t level, uint32_t optname, void* optval_ptr, uint32_t optlen) {
  if (level == 0xFFFF && (optname == 0x5801 || optname == 0x5802)) {
    // Disable socket encryption
    secure_ = false;
    return X_STATUS_SUCCESS;
  }

  // Guest titles use the Winsock socket-option ABI (SOL_SOCKET == 0xFFFF, and
  // SO_* codes that differ from POSIX). Translate the common SOL_SOCKET options
  // to their host equivalents; passing the Winsock codes straight to the host
  // setsockopt() fails. Unrecognized SOL_SOCKET options are accepted as no-ops
  // (benign for single-player) so net setup doesn't fail on them.
  int host_level = static_cast<int>(level);
  int host_opt = static_cast<int>(optname);
  if (level == 0xFFFF) {
    host_level = SOL_SOCKET;
    switch (optname) {
      case 0x0004:
        host_opt = SO_REUSEADDR;
        break;
      case 0x0008:
        host_opt = SO_KEEPALIVE;
        break;
      case 0x0010:
        host_opt = SO_DONTROUTE;
        break;
      case 0x0020:
        host_opt = SO_BROADCAST;
        broadcast_socket_ = true;
        break;
      case 0x0100:
        host_opt = SO_OOBINLINE;
        break;
      case 0x1001:
        host_opt = SO_SNDBUF;
        break;
      case 0x1002:
        host_opt = SO_RCVBUF;
        break;
      default:
        // Unsupported/struct-shaped (e.g. SO_LINGER) or title-specific option;
        // accept silently rather than failing the net subsystem.
        return X_STATUS_SUCCESS;
    }
  }

  int ret = setsockopt(native_handle_, host_level, host_opt, (char*)optval_ptr, optlen);
  if (ret < 0) {
    // TODO: WSAGetLastError()
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::IOControl(uint32_t cmd, uint8_t* arg_ptr) {
  int ret = rex::net::socket_ioctl(native_handle_, cmd, arg_ptr);
  if (ret < 0) {
    // TODO: Get last error
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::Connect(N_XSOCKADDR* name, int name_len) {
  int ret = connect(native_handle_, (sockaddr*)name, name_len);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::Bind(N_XSOCKADDR_IN* name, int name_len) {
  // NOTE: do NOT pin to a per-instance loopback IP here — a socket bound to 127.0.0.10 won't receive
  // the host's OWN MMHOST loopback self-connect (which targets 127.0.0.1), breaking host startup.
  // Same-box peer delivery is handled at the SendTo layer (port remap to the peer's real OS port).
  // [COD4MP-MMNETNS] In netns mode bind the REAL Xbox port on INADDR_ANY (0.0.0.0) in this instance's own
  // namespace (no same-box conflict) so the bound OS port == the Xbox port and the socket receives on BOTH
  // this ns's loopback (self-join) and its veth IP (peers) — no ephemeral remap, no NAT. The guest's
  // N_XSOCKADDR_IN family/addr often isn't directly bindable, so build a clean sockaddr_in with the
  // requested Xbox port (ntohs(name->sin_port) recovers it, same as the getsockname trace below).
  int ret = -1;
  if (Cod4NetnsMode() && name) {
    sockaddr_in want{};
    want.sin_family = AF_INET;
    want.sin_addr.s_addr = htonl(INADDR_ANY);
    want.sin_port = htons((uint16_t)ntohs((uint16_t)name->sin_port));  // the requested Xbox port (net order)
    ret = bind(native_handle_, (sockaddr*)&want, sizeof(want));
  } else {
    ret = bind(native_handle_, (sockaddr*)name, name_len);
  }
  if (ret < 0) {
    // Guest titles bind to fixed Xbox ports/addresses the host often can't grab
    // (privileged, already in use, or a non-local guest address). For single-
    // player the title only needs a usable bound socket, so fall back to an
    // ephemeral wildcard bind rather than failing the whole net subsystem.
    sockaddr_in fallback{};
    fallback.sin_family = AF_INET;
    fallback.sin_addr.s_addr = htonl(INADDR_ANY);
    fallback.sin_port = 0;  // let the OS pick a free port
    ret = bind(native_handle_, (sockaddr*)&fallback, sizeof(fallback));
    if (ret < 0) {
      return X_STATUS_UNSUCCESSFUL;
    }
  }

  bound_ = true;
  bound_port_ = name->sin_port;

  // [COD4MP-MMBROKER] Capture the REAL OS-assigned port (getsockname) — the guest only knows the Xbox
  // port it requested (often unbindable -> ephemeral fallback), so for cross-instance P2P we must
  // advertise the actual port. Trace requested-vs-real so we can identify the match/VDP socket.
  {
    sockaddr_in sa{};
    socklen_t sl = sizeof(sa);
    if (getsockname(native_handle_, (sockaddr*)&sa, &sl) == 0) {
      real_bound_port_ = ntohs(sa.sin_port);
      if (real_bound_port_ && g_host_real_port_count < 8) {
        g_host_guest_ports[g_host_real_port_count] = ntohs(name->sin_port);  // requested Xbox/guest port
        g_host_real_ports[g_host_real_port_count++] = real_bound_port_;
      }
    }
    const char* d = std::getenv("COD4_MM_REGISTRY");
    std::string path = std::string(d && d[0] ? d : "/tmp/cod4_mp_sessions") + "/nettrace.log";
    if (FILE* f = std::fopen(path.c_str(), "a")) {
      std::fprintf(f, "[pid %d] BIND fd=%d requested_xbox_port=%u -> real_os_port=%u\n",
                   (int)getpid(), (int)native_handle_, (unsigned)ntohs(name->sin_port),
                   (unsigned)real_bound_port_);
      std::fclose(f);
    }
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::Listen(int backlog) {
  int ret = listen(native_handle_, backlog);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

object_ref<XSocket> XSocket::Accept(N_XSOCKADDR* name, int* name_len) {
  sockaddr n_sockaddr;
  socklen_t n_name_len = sizeof(sockaddr);
  uintptr_t ret = accept(native_handle_, &n_sockaddr, &n_name_len);
  if (ret == -1) {
    std::memset(name, 0, *name_len);
    *name_len = 0;
    return nullptr;
  }

  std::memcpy(name, &n_sockaddr, n_name_len);
  *name_len = n_name_len;

  // Create a kernel object to represent the new socket, and copy parameters
  // over.
  auto socket = object_ref<XSocket>(new XSocket(kernel_state_, ret));
  socket->af_ = af_;
  socket->type_ = type_;
  socket->proto_ = proto_;

  return socket;
}

int XSocket::Shutdown(int how) {
  return shutdown(native_handle_, how);
}

int XSocket::Recv(uint8_t* buf, uint32_t buf_len, uint32_t flags) {
  return recv(native_handle_, reinterpret_cast<char*>(buf), buf_len, flags);
}

int XSocket::RecvFrom(uint8_t* buf, uint32_t buf_len, uint32_t flags, N_XSOCKADDR_IN* from,
                      uint32_t* from_len) {
  // Pop from secure packets first
  // TODO(DrChat): Enable when I commit XNet
  /*
  {
    std::lock_guard<std::mutex> lock(incoming_packet_mutex_);
    if (incoming_packets_.size()) {
      packet* pkt = (packet*)incoming_packets_.front();
      int data_len = pkt->data_len;
      std::memcpy(buf, pkt->data, std::min((uint32_t)pkt->data_len, buf_len));

      from->sin_family = 2;
      from->sin_addr = pkt->src_ip;
      from->sin_port = pkt->src_port;

      incoming_packets_.pop();
      uint8_t* pkt_ui8 = (uint8_t*)pkt;
      delete[] pkt_ui8;

      return data_len;
    }
  }
  */

  sockaddr_in nfrom;
  socklen_t nfromlen = sizeof(sockaddr_in);
  int ret = recvfrom(native_handle_, reinterpret_cast<char*>(buf), buf_len, flags,
                     (sockaddr*)&nfrom, &nfromlen);
  if (ret > 0) NetPktTrace("RECVFROM", nfrom.sin_addr.s_addr, nfrom.sin_port, ret, buf);  // [COD4MP-MMBROKER]
  if (from) {
    from->sin_family = nfrom.sin_family;
    uint32_t src_ip = ntohl(nfrom.sin_addr.s_addr);  // host order, e.g. 0x7F0000xx
    uint16_t src_port = ntohs(nfrom.sin_port);
    // [COD4MP-MMBROKER] Reverse of the SendTo remap: a reply from the peer host arrives from
    // 127.0.0.1:<its real OS port>, but the joiner's netchannel expects it from the sentinel it sent to
    // (127.0.0.2:<guest port>) and drops a source mismatch. Rewrite it back so the handshake completes.
    uint16_t rev_guest = 0;
    // [COD4MP-MMNETNS] netns mode: replies arrive from the peer's real veth IP (10.x), not the loopback
    // sentinel — present the source as-is so the title's netchannel accepts it (no reverse remap).
    if (!Cod4NetnsMode() && src_ip == 0x7F000001u) {
      rev_guest = PeerGuestForReal(src_port);                       // per-port: real game/lobby -> its guest
      if (!rev_guest && g_peer_real_port && src_port == g_peer_real_port)
        rev_guest = g_peer_guest_port;                              // fallback: single advertised port
      // [COD4MP-MMBROKER] COD4_MM_GAMEROUTE reverse: the SendTo reroute sent the GAME netchannel out the
      // game socket (guest 59651), but the title's netchannel connected to the VDP port (59395) and expects
      // replies FROM 59395. So a connected-netchannel reply arriving from the game socket must be presented
      // as 59395 (connectionless game-connect responses keep 59651). Symmetric to the SendTo reroute.
      static int gameroute = []{ const char* e = std::getenv("COD4_MM_GAMEROUTE"); return (e && e[0] && e[0] != '0') ? 1 : 0; }();
      if (gameroute && rev_guest == 59651 && ret >= 6 &&
          !(buf[2] == 0xFF && buf[3] == 0xFF && buf[4] == 0xFF && buf[5] == 0xFF))
        rev_guest = 59395;
    }
    if (rev_guest) {
      from->sin_addr = 0x7F000002u;                   // 127.0.0.2 (host order, the peer sentinel)
      from->sin_port = htons(rev_guest);              // the guest port the title sent to
    } else {
      from->sin_addr = src_ip;
      from->sin_port = nfrom.sin_port;
    }
    // [COD4MP-MMNETNS] Symmetric reverse of the SendTo game-port reroute: a connected-game reply/snapshot
    // arrives from the peer's GAME port (59651) but our netchannel addressed its VDP port (59395) and drops
    // a source mismatch — present it as 59395 (keep the real IP). src_port==59651 only matches the host's
    // game-server source (a joiner's own send source differs), so this is safe on both host and joiner.
    if (Cod4NetnsMode() && !Cod4NoReroute() && src_port == 59651 && ret >= 6 &&
        !(buf[2] == 0xFF && buf[3] == 0xFF && buf[4] == 0xFF && buf[5] == 0xFF)) {
      from->sin_addr = src_ip;
      from->sin_port = htons(59395);
    }
    std::memset(from->x_sin_zero, 0, sizeof(from->x_sin_zero));
  }

  if (from_len) {
    *from_len = nfromlen;
  }

  return ret;
}

int XSocket::Send(const uint8_t* buf, uint32_t buf_len, uint32_t flags) {
  return send(native_handle_, reinterpret_cast<const char*>(buf), buf_len, flags);
}

int XSocket::SendTo(uint8_t* buf, uint32_t buf_len, uint32_t flags, N_XSOCKADDR_IN* to,
                    uint32_t to_len) {
  // Send 2 copies of the packet: One to XNet (for network security) and an
  // unencrypted copy for other Xenia hosts.
  // TODO(DrChat): Enable when I commit XNet.
  /*
  auto xam = kernel_state()->GetKernelModule<xam::XamModule>("xam.xex");
  auto xnet = xam->xnet();
  if (xnet) {
    xnet->SendPacket(this, to, buf, buf_len);
  }
  */

  sockaddr_in nto;
  if (to) {
    nto.sin_family = to->sin_family;
    nto.sin_port = to->sin_port;
    // [COD4MP-MMBROKER] The guest hands sin_addr in HOST byte order (RecvFrom stores it via ntohl), so
    // convert to network order for the host sendto — without this the host's reply to a joiner goes out
    // as the byte-flipped 1.0.0.127 and never arrives. (host order: 127 is the HIGH byte, e.g. 0x7F0000xx)
    uint32_t hip = to->sin_addr;
    nto.sin_addr.s_addr = htonl(hip);
    // Same-box peer delivery: the joiner sends to the peer sentinel 127.0.0.x (x!=1) at the peer's FIXED
    // guest port; the host's sockets were ephemeral-remapped, so rewrite to 127.0.0.1:<host real port>.
    // PER-GUEST-PORT: route to the host's real port FOR THIS GUEST PORT (lobby 59395->lobby socket, game
    // 59651->game listen socket). Falls back to the single advertised port (g_peer_real_port) if the map
    // is missing the guest port — without per-port routing a game-connect was misrouted to the lobby
    // socket which replied "disconnect" -> joiner gave up -> "Game lobby closed".
    uint16_t guest_dst = ntohs(to->sin_port);
    // [COD4MP-MMBROKER] COD4_MM_GAMEROUTE: the title sends the connected GAME netchannel to its FIXED VDP
    // guest port (59395 = the lobby/party socket), but the host's listen SERVER is on the GAME socket
    // (guest 59651). So game data hits the host's party socket, the SV never sees it, and the in-progress
    // joiner gets timed out at PRIMED. Connected netchannel packets are distinguishable from party/connect
    // traffic by payload: [2B length][payload]; payload[0..3]==0xFFFFFFFF = connectionless (party/connect),
    // else = connected netchannel (game). Route connected netchannel to the GAME guest port so the SV gets it.
    static int gameroute = []{ const char* e = std::getenv("COD4_MM_GAMEROUTE"); return (e && e[0] && e[0] != '0') ? 1 : 0; }();
    uint16_t route_guest = guest_dst;
    if (!Cod4NetnsMode() && gameroute && buf && buf_len >= 6 &&
        !(buf[2] == 0xFF && buf[3] == 0xFF && buf[4] == 0xFF && buf[5] == 0xFF) &&
        PeerRealForGuest(59651))
      route_guest = 59651;  // connected netchannel -> the host's game listen socket
    // [COD4MP-MMNETNS] Distinct real IPs (no NAT) BUT the title still addresses the connected GAME
    // netchannel to the peer's VDP port (59395) while the host's game server listens on the GAME port
    // (59651). Reroute connected-game packets to 59651 (keeping the peer's REAL IP) so the SV receives
    // them; connectionless party/connect (0xFFFFFFFF) stays on the advertised VDP port.
    if (Cod4NetnsMode() && !Cod4NoReroute() && guest_dst == 59395 && buf && buf_len >= 6 &&
        !(buf[2] == 0xFF && buf[3] == 0xFF && buf[4] == 0xFF && buf[5] == 0xFF))
      nto.sin_port = htons(59651);
    // [COD4MP-MMNETNS] netns mode: peer is a real distinct IP (10.x), so send straight to it — skip the
    // same-box 127.0.0.x port-NAT entirely (the condition below is already false for 10.x, but be explicit).
    if (!Cod4NetnsMode() && ((hip >> 24) & 0xFF) == 127 && (hip & 0xFF) != 1) {
      uint16_t real_dst = PeerRealForGuest(route_guest);
      if (!real_dst) real_dst = g_peer_real_port;  // fallback: advertised (lobby) port
      if (real_dst) {
        g_peer_guest_port = guest_dst;              // remember for the RecvFrom rewrite (fallback path)
        nto.sin_addr.s_addr = htonl(0x7F000001u);   // 127.0.0.1
        nto.sin_port = htons(real_dst);             // host's real OS port for this guest port
      }
    }
  }

  if (to) NetPktTrace("SENDTO", nto.sin_addr.s_addr, nto.sin_port, (int)buf_len, buf);  // [COD4MP-MMBROKER]
  // [COD4MP-MMBROKER] pre-NAT guest-dst log (NetPktTrace logs the POST-NAT port, so it can't tell a
  // game-connect from a lobby packet). Reveals which guest port the title actually targets.
  if (to && g_peer_map_count > 0) {
    uint32_t hip2 = to->sin_addr;
    if (((hip2 >> 24) & 0xFF) == 127 && (hip2 & 0xFF) != 1)
      NetPktTrace("SENDTO-GUEST", htonl(hip2), to->sin_port, (int)buf_len);
  }
  // [COD4MP-MMBROKER] COD4_MM_NOKICK=1: drop the host's `endparty XBOXLIVE_NOTREGISTEREDWITHARBITRATION`
  // datagram so the joiner is NOT kicked when the host takes the abort->start path (COD4_MM_ARBEMPTY). The
  // payload is connectionless: 2B len + 0xFFFFFFFF + '0' + "endparty <reason>". Report success (as if sent).
  static int nokick = []{ const char* e = std::getenv("COD4_MM_NOKICK"); return (e && e[0] && e[0] != '0') ? 1 : 0; }();
  if (nokick && buf && buf_len > 16) {
    auto contains = [&](const char* needle, size_t nl) -> bool {
      if (buf_len < nl) return false;
      for (size_t i = 0; i + nl <= buf_len; i++)
        if (std::memcmp(buf + i, needle, nl) == 0) return true;
      return false;
    };
    // Drop ANY endparty (NOTREGISTEREDWITHARBITRATION on the abort-start path, and
    // PLATFORM_DISCONNECTED when the host's XNet connection-status check on the joiner fails) so the host
    // can't drop the joiner mid-join.
    if (contains("endparty", 8)) {
      NetPktTrace("DROP-ENDPARTY", nto.sin_addr.s_addr, nto.sin_port, (int)buf_len, buf);
      return (int)buf_len;
    }
  }
  return sendto(native_handle_, reinterpret_cast<char*>(buf), buf_len, flags,
                to ? (sockaddr*)&nto : nullptr, to_len);
}

bool XSocket::QueuePacket(uint32_t src_ip, uint16_t src_port, const uint8_t* buf, size_t len) {
  packet* pkt = reinterpret_cast<packet*>(new uint8_t[sizeof(packet) + len]);
  pkt->src_ip = src_ip;
  pkt->src_port = src_port;

  pkt->data_len = (uint16_t)len;
  std::memcpy(pkt->data, buf, len);

  std::lock_guard<std::mutex> lock(incoming_packet_mutex_);
  incoming_packets_.push((uint8_t*)pkt);

  // TODO: Limit on number of incoming packets?
  return true;
}

}  // namespace rex::system