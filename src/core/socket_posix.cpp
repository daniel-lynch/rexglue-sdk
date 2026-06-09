#include <rex/net/socket.h>
#include <rex/platform.h>

static_assert(REX_PLATFORM_LINUX || REX_PLATFORM_MAC, "This file is POSIX-only");

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cstring>

namespace rex::net {

int socket_close(SocketHandle handle) {
  return close(static_cast<int>(handle));
}

int socket_ioctl(SocketHandle handle, uint32_t cmd, uint8_t* arg) {
  int fd = static_cast<int>(handle);

  // Guest titles use the Xbox/Winsock ioctl ABI, whose command codes differ
  // from POSIX. Translate the common case -- FIONBIO (set non-blocking) -- to
  // fcntl(O_NONBLOCK); passing the Winsock code straight to ioctl() fails.
  constexpr uint32_t kWinsockFIONBIO = 0x8004667Eu;  // _IOW('f', 126, u_long)
  if (cmd == kWinsockFIONBIO) {
    uint32_t enable = 0;
    if (arg) {
      std::memcpy(&enable, arg, sizeof(enable));  // any nonzero == enable
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
      return -1;
    }
    if (enable) {
      flags |= O_NONBLOCK;
    } else {
      flags &= ~O_NONBLOCK;
    }
    return fcntl(fd, F_SETFL, flags);
  }

  return ioctl(fd, cmd, arg);
}

}  // namespace rex::net
