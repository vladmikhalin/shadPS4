// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "common/assert.h"
#include "common/indexed_resources.h"
#include "common/logging/log.h"
#include "core/libraries/error_codes.h"
#include "core/libraries/kernel/thread_management.h"
#include "core/libraries/libs.h"
#include "core/libraries/network/net.h"
#include "error_codes.h"

#include <functional>
#include <optional>
#include <shared_mutex>

#ifdef WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Ws2tcpip.h>
#include <iphlpapi.h>
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

namespace Libraries::Net {

#define orbis_net_errno (*sceNetErrnoLoc())

#ifdef WIN32
struct SocketInternal {};
static IndexedResources<OrbisNetId, SocketInternal> g_index_manager;
#endif

struct OrbisNetSync {
    int Init(s32 init, const char* name) {
        mutex = nullptr;
        auto res = Kernel::scePthreadMutexInit(&mutex, nullptr, name);
        if (res < 0) {
            return res;
        }
        cond = nullptr;
        res = Kernel::scePthreadCondInit(&cond, nullptr, name);
        if (res < 0) {
            Kernel::scePthreadMutexDestroy(&mutex);
            return res;
        }
        this->init = init;
        return 0;
    }

    ~OrbisNetSync() {
        init = false;
        if (cond != nullptr) {
            Kernel::scePthreadCondDestroy(&cond);
        }
        if (mutex != nullptr) {
            Kernel::scePthreadMutexDestroy(&mutex);
        }
    }

    Kernel::ScePthreadMutex mutex = nullptr;
    Kernel::ScePthreadCond cond = nullptr;
    s32 init = 0;
};

struct OrbisNetGlobalState {
    OrbisNetGlobalState() {
        Init();
    }

    int Init() {
        if (is_initialized) {
            return 0;
        }
        auto res = dhcp_sync.Init(1, "LibnetSync");
        if (res < 0) {
            return res;
        }
        res = dhcp_sync.Init(1, "DhcpSync");
        if (res < 0) {
            return res;
        }
        res = dhcpd_sync.Init(1, "DhcpdSync");
        if (res < 0) {
            return res;
        }
        res = dup_ip_det_sync.Init(1, "DupIpDetSync");
        if (res < 0) {
            return res;
        }
        res = net_addrconfig6_sync.Init(1, "Addrconfig6Sync");
        if (res < 0) {
            return res;
        }
        res = info_sync.Init(1, "InfoSync");
        if (res < 0) {
            return res;
        }
        // FUN_01009640((GlobalState *)&DAT_0104c1e8,(unk1 *)&DAT_0103c108,0x10000,0);
        is_initialized = true;
        return 0;
    }

    bool is_initialized = false;

    OrbisNetSync libnet_sync;
    OrbisNetSync dhcp_sync;
    OrbisNetSync dhcpd_sync;
    OrbisNetSync dup_ip_det_sync;
    OrbisNetSync net_addrconfig6_sync;
    OrbisNetSync info_sync;

    OrbisNetSync mem_sync;
};

// static OrbisNetGlobalState g_net_state;

#ifdef WIN32
WSADATA Init() {
    WSADATA data{};
    WSAStartup(MAKEWORD(2, 2), &data);
    return data;
}

static WSADATA wsaData = Init();
#else
#define INVALID_SOCKET -1
#endif

#ifndef WIN32
#define POSIX_ERRNO_CASES                                                                          \
    CASE(EPERM)                                                                                    \
    CASE(ENOENT)                                                                                   \
    CASE(ESRCH)                                                                                    \
    CASE(EIO)                                                                                      \
    CASE(ENXIO)                                                                                    \
    CASE(E2BIG)                                                                                    \
    CASE(ENOEXEC)                                                                                  \
    CASE(EDEADLK)                                                                                  \
    CASE(ENOMEM)                                                                                   \
    CASE(ECHILD)                                                                                   \
    CASE(EBUSY)                                                                                    \
    CASE(EEXIST)                                                                                   \
    CASE(EXDEV)                                                                                    \
    CASE(ENODEV)                                                                                   \
    CASE(ENOTDIR)                                                                                  \
    CASE(EISDIR)                                                                                   \
    CASE(ENFILE)                                                                                   \
    CASE(ENOTTY)                                                                                   \
    CASE(ETXTBSY)                                                                                  \
    CASE(EFBIG)                                                                                    \
    CASE(ENOSPC)                                                                                   \
    CASE(ESPIPE)                                                                                   \
    CASE(EROFS)                                                                                    \
    CASE(EMLINK)                                                                                   \
    CASE(EPIPE)                                                                                    \
    CASE(EDOM)                                                                                     \
    CASE(ERANGE)                                                                                   \
    CASE(ENOLCK)                                                                                   \
    CASE(ENOSYS)                                                                                   \
    CASE(EIDRM)                                                                                    \
    CASE(EOVERFLOW)                                                                                \
    CASE(EILSEQ)                                                                                   \
    CASE(ENOTSUP)                                                                                  \
    CASE(ECANCELED)                                                                                \
    CASE(EBADMSG)                                                                                  \
    CASE(ENODATA)                                                                                  \
    CASE(ENOSR)                                                                                    \
    CASE(ENOSTR)                                                                                   \
    CASE(ETIME)
#else
#define POSIX_ERRNO_CASES
#endif

#if defined(__APPLE__) || defined(WIN32)
#define APPLE_WIN32_ERRNO_CASES CASE(EOPNOTSUPP)
#else
#define APPLE_WIN32_ERRNO_CASES
#endif

#define ERRNO_CASES                                                                                \
    POSIX_ERRNO_CASES                                                                              \
    APPLE_WIN32_ERRNO_CASES                                                                        \
    CASE(EINTR)                                                                                    \
    CASE(EBADF)                                                                                    \
    CASE(EACCES)                                                                                   \
    CASE(EFAULT)                                                                                   \
    CASE(EINVAL)                                                                                   \
    CASE(EMFILE)                                                                                   \
    CASE(EWOULDBLOCK)                                                                              \
    CASE(EINPROGRESS)                                                                              \
    CASE(EALREADY)                                                                                 \
    CASE(ENOTSOCK)                                                                                 \
    CASE(EDESTADDRREQ)                                                                             \
    CASE(EMSGSIZE)                                                                                 \
    CASE(EPROTOTYPE)                                                                               \
    CASE(ENOPROTOOPT)                                                                              \
    CASE(EPROTONOSUPPORT)                                                                          \
    CASE(EAFNOSUPPORT)                                                                             \
    CASE(EADDRINUSE)                                                                               \
    CASE(EADDRNOTAVAIL)                                                                            \
    CASE(ENETDOWN)                                                                                 \
    CASE(ENETUNREACH)                                                                              \
    CASE(ENETRESET)                                                                                \
    CASE(ECONNABORTED)                                                                             \
    CASE(ECONNRESET)                                                                               \
    CASE(ENOBUFS)                                                                                  \
    CASE(EISCONN)                                                                                  \
    CASE(ENOTCONN)                                                                                 \
    CASE(ETIMEDOUT)                                                                                \
    CASE(ECONNREFUSED)                                                                             \
    CASE(ELOOP)                                                                                    \
    CASE(ENAMETOOLONG)                                                                             \
    CASE(EHOSTUNREACH)                                                                             \
    CASE(ENOTEMPTY)

#ifdef WIN32
#define net_errno (WSAGetLastError())
#else
#define net_errno errno
#endif

static int ToOrbisNetError(int err) {
    switch (err) {
#ifdef WIN32
#define CASE(err)                                                                                  \
    case WSA##err:                                                                                 \
        return ORBIS_NET_ERROR_##err;
#else
#define CASE(err)                                                                                  \
    case (err):                                                                                    \
        return ORBIS_NET_ERROR_##err;
#endif
        ERRNO_CASES
#undef CASE
    default:
        return ORBIS_NET_ERROR_EINTERNAL;
    }
}

static int ToOrbisNetErrno(int err) {
    switch (err) {
#ifdef WIN32
#define CASE(err)                                                                                  \
    case WSA##err:                                                                                 \
        return ORBIS_NET_##err;
#else
#define CASE(err)                                                                                  \
    case (err):                                                                                    \
        return ORBIS_NET_##err;
#endif
        ERRNO_CASES
#undef CASE
    default:
        return ORBIS_NET_EINTERNAL;
    }
}

static void ToOrbisSockaddr(const sockaddr& src, OrbisNetSockaddr& dst) {
    dst = OrbisNetSockaddr{};
    const auto& src_sin = reinterpret_cast<const sockaddr_in&>(src);
    auto& dst_sin = reinterpret_cast<OrbisNetSockaddrIn&>(dst);
    dst_sin.sin_len = sizeof(OrbisNetSockaddrIn);
    dst_sin.sin_family = src_sin.sin_family;
    dst_sin.sin_port = src_sin.sin_port;
    std::memcpy(&dst_sin.sin_addr, &src_sin.sin_addr, 4);
}

static void FromOrbisSockaddr(const OrbisNetSockaddr& src, sockaddr& dst) {
    auto& dst_sin = reinterpret_cast<sockaddr_in&>(dst);
    const auto& src_sin = reinterpret_cast<const OrbisNetSockaddrIn&>(src);
    dst_sin.sin_family = src_sin.sin_family;
    dst_sin.sin_port = src_sin.sin_port;
    memcpy(&dst_sin.sin_addr, &src_sin.sin_addr, 4);
}

static int NetError(int err) {
    orbis_net_errno = ToOrbisNetErrno(err);
    return ToOrbisNetError(err);
}

OrbisNetId PS4_SYSV_ABI sceNetAccept(OrbisNetId s, OrbisNetSockaddr* paddr, u32* paddrlen) {
    LOG_TRACE(Lib_Net, "called, s = {}", s);
    if (paddr == nullptr) {
        return NetError(EINVAL);
    }
    sockaddr addr{};
    int addrlen = sizeof(sockaddr_in);
    auto sock = accept(s, &addr, &addrlen);
    if (sock == INVALID_SOCKET) {
        return NetError(net_errno);
    }
    ToOrbisSockaddr(addr, *paddr);
    *paddrlen = sizeof(OrbisNetSockaddrIn);
    return sock;
}

int PS4_SYSV_ABI sceNetBind(OrbisNetId s, const OrbisNetSockaddr* paddr, u32 addrlen) {
    LOG_TRACE(Lib_Net, "called, s = {}", s);
    if (paddr == nullptr) {
        return NetError(EINVAL);
    }
    sockaddr addr{};
    FromOrbisSockaddr(*paddr, addr);
    const auto res = bind(s, &addr, sizeof(sockaddr_in));
    if (res < 0) {
        return NetError(net_errno);
    }
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConnect(OrbisNetId s, const OrbisNetSockaddr* paddr, u32 addrlen) {
    LOG_TRACE(Lib_Net, "called, s = {}", s);
    if (paddr == nullptr) {
        return NetError(EINVAL);
    }
    sockaddr addr{};
    FromOrbisSockaddr(*paddr, addr);
    const auto res = connect(s, &addr, sizeof(sockaddr_in));
    if (res < 0) {
        return NetError(net_errno);
    }
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetGetpeername(OrbisNetId s, OrbisNetSockaddr* paddr, u32* paddrlen) {
    LOG_TRACE(Lib_Net, "called, s = {}", s);
    if (paddr == nullptr || paddrlen == nullptr) {
        return NetError(EINVAL);
    }
    sockaddr addr{};
    int addrlen = sizeof(sockaddr_in);
    const auto res = getpeername(s, &addr, &addrlen);
    if (res < 0) {
        return NetError(net_errno);
    }
    ToOrbisSockaddr(addr, *paddr);
    *paddrlen = sizeof(OrbisNetSockaddrIn);
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetGetsockname(OrbisNetId s, OrbisNetSockaddr* paddr, u32* paddrlen) {
    LOG_TRACE(Lib_Net, "called, s = {}", s);
    if (paddr == nullptr || paddrlen == nullptr) {
        return NetError(EINVAL);
    }
    sockaddr addr{};
    int addrlen = sizeof(sockaddr_in);
    const auto res = getsockname(s, &addr, &addrlen);
    if (res < 0) {
        return NetError(net_errno);
    }
    ToOrbisSockaddr(addr, *paddr);
    *paddrlen = sizeof(OrbisNetSockaddrIn);
    return ORBIS_OK;
}

#ifdef WIN32
#ifndef SO_REUSEPORT
#define SO_REUSEPORT SO_REUSEADDR
#endif
#endif

static int FromOrbisOptlevel(int level) {
    switch (level) {
#define CASE(level)                                                                                \
    case ORBIS_NET_##level:                                                                        \
        return level
        CASE(IPPROTO_IP);
        CASE(IPPROTO_ICMP);
        CASE(IPPROTO_IGMP);
        CASE(IPPROTO_TCP);
        CASE(IPPROTO_UDP);
        CASE(SOL_SOCKET);
    default:
        UNREACHABLE_MSG("Unexpected optlevel");
    }
}

int FromOrbisSocketOptname(int optname) {
    switch (optname) {
#define CASE(name)                                                                                 \
    case ORBIS_NET_##name:                                                                         \
        return name
        CASE(SO_REUSEADDR);
        CASE(SO_KEEPALIVE);
        CASE(SO_BROADCAST);
        CASE(SO_LINGER);
        CASE(SO_REUSEPORT);
        CASE(SO_SNDBUF);
        CASE(SO_RCVBUF);
        CASE(SO_ERROR);
        CASE(SO_TYPE);
        CASE(SO_SNDTIMEO);
        CASE(SO_RCVTIMEO);
#undef CASE
        // CASE(SO_ONESBCAST);
        // CASE(SO_USECRYPTO);
        // CASE(SO_USESIGNATURE);
        // CASE(SO_ERROR_EX);
        // CASE(SO_ACCEPTTIMEO);
        // CASE(SO_CONNECTTIMEO);
        // CASE(SO_NBIO);
        // CASE(SO_POLICY);
        // CASE(SO_NAME);
        // CASE(SO_PRIORITY);
    default:
        LOG_ERROR(Lib_Net, "Unsupported socket optname 0x%08X", optname);
        return -1;
    }
}

int PS4_SYSV_ABI sceNetGetsockopt(OrbisNetId s, int level, int optname, void* optval, u32* optlen) {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    switch (level) {
    case ORBIS_NET_IPPROTO_IP:
    case ORBIS_NET_IPPROTO_ICMP:
    case ORBIS_NET_IPPROTO_IGMP:
    case ORBIS_NET_IPPROTO_TCP:
    case ORBIS_NET_IPPROTO_UDP:
    case ORBIS_NET_SOL_SOCKET: {
        switch (optname) {
        case ORBIS_NET_SO_NBIO: {
            DWORD ret;
            WSAIoctl(s, FIONBIO, nullptr, 0, optval, *optlen, &ret, nullptr, nullptr);
            break;
        }
        default:
            break;
        }
    }
    }

    optname = FromOrbisSocketOptname(optname);
    if (optname < 0) {
        // Can't do anything with those, just return OK
        return ORBIS_OK;
    }
    level = FromOrbisOptlevel(level);
    getsockopt(s, level, optname, reinterpret_cast<char*>(optval), reinterpret_cast<int*>(optlen));
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetListen(OrbisNetId s, int backlog) {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetRecv(OrbisNetId s, void* buf, size_t len, int flags) {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetRecvfrom(OrbisNetId s, void* buf, size_t len, int flags,
                                OrbisNetSockaddr* addr, u32* paddrlen) {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetRecvmsg(OrbisNetId s, OrbisNetMsghdr* msg, int flags) {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetSend(OrbisNetId s, const void* buf, size_t len, int flags) {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetSendmsg(OrbisNetId s, const OrbisNetMsghdr* msg, int flags) {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetSendto(OrbisNetId s, const void* buf, size_t len, int flags,
                              const OrbisNetSockaddr* addr, u32 addrlen) {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetSetsockopt(OrbisNetId s, int level, int optname, const void* optval,
                                  u32 optlen) {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetShutdown(OrbisNetId s, int how) {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetSocket(const char* name, int family, int type, int protocol) {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetSocketAbort(OrbisNetId s, int flags) {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetSocketClose(OrbisNetId s) {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetAddrConfig6GetInfo() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetAddrConfig6Start() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetAddrConfig6Stop() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetAllocateAllRouteInfo() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetBandwidthControlGetDataTraffic() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetBandwidthControlGetDefaultParam() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetBandwidthControlGetIfParam() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetBandwidthControlGetPolicy() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetBandwidthControlSetDefaultParam() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetBandwidthControlSetIfParam() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetBandwidthControlSetPolicy() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetClearDnsCache() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigAddArp() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigAddArpWithInterface() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigAddIfaddr() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigAddMRoute() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigAddRoute() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigAddRoute6() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigAddRouteWithInterface() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigCleanUpAllInterfaces() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigDelArp() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigDelArpWithInterface() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigDelDefaultRoute() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigDelDefaultRoute6() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigDelIfaddr() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigDelIfaddr6() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigDelMRoute() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigDelRoute() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigDelRoute6() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigDownInterface() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigEtherGetLinkMode() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigEtherPostPlugInOutEvent() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigEtherSetLinkMode() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigFlushRoute() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigGetDefaultRoute() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigGetDefaultRoute6() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigGetIfaddr() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigGetIfaddr6() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigRoutingShowRoutingConfig() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigRoutingShowtCtlVar() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigRoutingStart() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigRoutingStop() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigSetDefaultRoute() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigSetDefaultRoute6() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigSetDefaultScope() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigSetIfaddr() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigSetIfaddr6() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigSetIfaddr6WithFlags() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigSetIfFlags() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigSetIfLinkLocalAddr6() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigSetIfmtu() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigUnsetIfFlags() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigUpInterface() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigUpInterfaceWithFlags() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigWlanAdhocClearWakeOnWlan() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigWlanAdhocCreate() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigWlanAdhocGetWakeOnWlanInfo() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigWlanAdhocJoin() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigWlanAdhocLeave() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigWlanAdhocPspEmuClearWakeOnWlan() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigWlanAdhocPspEmuGetWakeOnWlanInfo() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigWlanAdhocPspEmuSetWakeOnWlan() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigWlanAdhocScanJoin() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigWlanAdhocSetExtInfoElement() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigWlanAdhocSetWakeOnWlan() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigWlanApStart() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigWlanApStop() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigWlanBackgroundScanQuery() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigWlanBackgroundScanStart() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigWlanBackgroundScanStop() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigWlanDiagGetDeviceInfo() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigWlanDiagSetAntenna() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigWlanDiagSetTxFixedRate() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigWlanGetDeviceConfig() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigWlanInfraGetRssiInfo() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigWlanInfraLeave() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigWlanInfraScanJoin() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigWlanScan() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetConfigWlanSetDeviceConfig() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetControl() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetDhcpdStart() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetDhcpdStop() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetDhcpGetAutoipInfo() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetDhcpGetInfo() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetDhcpGetInfoEx() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetDhcpStart() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetDhcpStop() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetDumpAbort() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetDumpCreate() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetDumpDestroy() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetDumpRead() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetDuplicateIpStart() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetDuplicateIpStop() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetEpollAbort() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetEpollControl() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetEpollCreate() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetEpollDestroy() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetEpollWait() {
    LOG_TRACE(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

static thread_local int g_sce_net_errno;
int* PS4_SYSV_ABI sceNetErrnoLoc() {
    LOG_TRACE(Lib_Net, "called");
    return &g_sce_net_errno;
}

int PS4_SYSV_ABI sceNetEtherNtostr() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetEtherStrton() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetEventCallbackCreate() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetEventCallbackDestroy() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetEventCallbackGetError() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetEventCallbackWaitCB() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetFreeAllRouteInfo() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetGetArpInfo() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetGetDns6Info() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetGetDnsInfo() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetGetIfList() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetGetIfListOnce() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetGetIfName() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetGetIfnameNumList() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetGetMacAddress() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetGetMemoryPoolStats() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetGetNameToIndex() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetGetRandom() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetGetRouteInfo() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetGetSockInfo() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetGetSockInfo6() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetGetStatisticsInfo() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetGetStatisticsInfoInternal() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetGetSystemTime() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

u32 PS4_SYSV_ABI sceNetHtonl(u32 host32) {
    return htonl(host32);
}

u64 PS4_SYSV_ABI sceNetHtonll(u64 host64) {
    return HTONLL(host64);
}

u16 PS4_SYSV_ABI sceNetHtons(u16 host16) {
    return htons(host16);
}

const char* PS4_SYSV_ABI sceNetInetNtop(int af, const void* src, char* dst, u32 size) {
#ifdef WIN32
    const char* res = InetNtopA(af, src, dst, size);
#else
    const char* res = inet_ntop(af, src, dst, size);
#endif
    if (res == nullptr) {
        UNREACHABLE();
    }
    return dst;
}

int PS4_SYSV_ABI sceNetInetNtopWithScopeId() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetInetPton(int af, const char* src, void* dst) {
#ifdef WIN32
    int res = InetPtonA(af, src, dst);
#else
    int res = inet_pton(af, src, dst);
#endif
    if (res < 0) {
        UNREACHABLE();
    }
    return res;
}

int PS4_SYSV_ABI sceNetInetPtonEx() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetInetPtonWithScopeId() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetInfoDumpStart() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetInfoDumpStop() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetInit() {
    LOG_ERROR(Lib_Net, "(DUMMY) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetInitParam() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetIoctl() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetMemoryAllocate() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetMemoryFree() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

u32 PS4_SYSV_ABI sceNetNtohl(u32 net32) {
    return ntohl(net32);
}

int PS4_SYSV_ABI sceNetNtohll() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

u16 PS4_SYSV_ABI sceNetNtohs(u16 net16) {
    return ntohs(net16);
}

int PS4_SYSV_ABI sceNetPoolCreate(const char* name, int size, int flags) {
    LOG_ERROR(Lib_Net, "(DUMMY) name = {} size = {} flags = {} ", std::string(name), size, flags);
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetPoolDestroy() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetPppoeStart() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetPppoeStop() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetResolverAbort() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetResolverConnect() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetResolverConnectAbort() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetResolverConnectCreate() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetResolverConnectDestroy() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetResolverCreate() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetResolverDestroy() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetResolverGetError() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetResolverStartAton() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetResolverStartAton6() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetResolverStartNtoa() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetResolverStartNtoa6() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetResolverStartNtoaMultipleRecords() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetResolverStartNtoaMultipleRecordsEx() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetSetDns6Info() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetSetDns6InfoToKernel() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetSetDnsInfo() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetSetDnsInfoToKernel() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetShowIfconfig() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetShowIfconfigForBuffer() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetShowIfconfigWithMemory() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetShowNetstat() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetShowNetstatEx() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetShowNetstatExForBuffer() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetShowNetstatForBuffer() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetShowNetstatWithMemory() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetShowPolicy() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetShowPolicyWithMemory() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetShowRoute() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetShowRoute6() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetShowRoute6ForBuffer() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetShowRoute6WithMemory() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetShowRouteForBuffer() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetShowRouteWithMemory() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetSyncCreate() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetSyncDestroy() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetSyncGet() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetSyncSignal() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetSyncWait() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetSysctl() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetTerm() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetThreadCreate() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetThreadExit() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetThreadJoin() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetUsleep() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI Func_0E707A589F751C68() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetEmulationGet() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNetEmulationSet() {
    LOG_ERROR(Lib_Net, "(STUBBED) called");
    return ORBIS_OK;
}

OrbisNetIn6Addr g_in6addr_any{.sin_addr = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
OrbisNetIn6Addr g_in6addr_loopback{.sin_addr = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
OrbisNetIn6Addr g_in6addr_dummy{.sin_addr = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
OrbisNetIn6Addr g_sce_net_in6addr_linklocal_allnodes{
    .sin_addr = {255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
OrbisNetIn6Addr g_sce_net_in6addr_linklocal_allrouters{
    .sin_addr = {255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}};
OrbisNetIn6Addr g_sce_net_in6addr_any{.sin_addr = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
OrbisNetIn6Addr g_sce_net_in6addr_loopback{
    .sin_addr = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
OrbisNetIn6Addr g_sce_net_in6addr_nodelocal_allnodes{
    .sin_addr = {255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};

void RegisterlibSceNet(Core::Loader::SymbolsResolver* sym) {
    LIB_OBJ("ZRAJo-A-ukc", "libSceNet", 1, "libSceNet", 1, 1, &g_in6addr_any);
    LIB_OBJ("XCuA-GqjA-k", "libSceNet", 1, "libSceNet", 1, 1, &g_in6addr_loopback);
    LIB_OBJ("VZgoeBxPXUQ", "libSceNet", 1, "libSceNet", 1, 1, &g_in6addr_dummy);
    LIB_OBJ("GAtITrgxKDE", "libSceNet", 1, "libSceNet", 1, 1, &g_sce_net_in6addr_any);
    LIB_OBJ("84MgU4MMTLQ", "libSceNet", 1, "libSceNet", 1, 1,
            &g_sce_net_in6addr_linklocal_allnodes);
    LIB_OBJ("2uSWyOKYc1M", "libSceNet", 1, "libSceNet", 1, 1,
            &g_sce_net_in6addr_linklocal_allrouters);
    LIB_OBJ("P3AeWBvPrkg", "libSceNet", 1, "libSceNet", 1, 1, &g_sce_net_in6addr_loopback);
    LIB_OBJ("PgNI+j4zxzM", "libSceNet", 1, "libSceNet", 1, 1,
            &g_sce_net_in6addr_nodelocal_allnodes);

    LIB_FUNCTION("PIWqhn9oSxc", "libSceNet", 1, "libSceNet", 1, 1, sceNetAccept);
    LIB_FUNCTION("bErx49PgxyY", "libSceNet", 1, "libSceNet", 1, 1, sceNetBind);
    LIB_FUNCTION("OXXX4mUk3uk", "libSceNet", 1, "libSceNet", 1, 1, sceNetConnect);
    LIB_FUNCTION("TCkRD0DWNLg", "libSceNet", 1, "libSceNet", 1, 1, sceNetGetpeername);
    LIB_FUNCTION("hoOAofhhRvE", "libSceNet", 1, "libSceNet", 1, 1, sceNetGetsockname);
    LIB_FUNCTION("xphrZusl78E", "libSceNet", 1, "libSceNet", 1, 1, sceNetGetsockopt);
    LIB_FUNCTION("kOj1HiAGE54", "libSceNet", 1, "libSceNet", 1, 1, sceNetListen);
    LIB_FUNCTION("9wO9XrMsNhc", "libSceNet", 1, "libSceNet", 1, 1, sceNetRecv);
    LIB_FUNCTION("304ooNZxWDY", "libSceNet", 1, "libSceNet", 1, 1, sceNetRecvfrom);
    LIB_FUNCTION("wvuUDv0jrMI", "libSceNet", 1, "libSceNet", 1, 1, sceNetRecvmsg);
    LIB_FUNCTION("beRjXBn-z+o", "libSceNet", 1, "libSceNet", 1, 1, sceNetSend);
    LIB_FUNCTION("2eKbgcboJso", "libSceNet", 1, "libSceNet", 1, 1, sceNetSendmsg);
    LIB_FUNCTION("gvD1greCu0A", "libSceNet", 1, "libSceNet", 1, 1, sceNetSendto);
    LIB_FUNCTION("2mKX2Spso7I", "libSceNet", 1, "libSceNet", 1, 1, sceNetSetsockopt);
    LIB_FUNCTION("TSM6whtekok", "libSceNet", 1, "libSceNet", 1, 1, sceNetShutdown);
    LIB_FUNCTION("Q4qBuN-c0ZM", "libSceNet", 1, "libSceNet", 1, 1, sceNetSocket);
    LIB_FUNCTION("zJGf8xjFnQE", "libSceNet", 1, "libSceNet", 1, 1, sceNetSocketAbort);
    LIB_FUNCTION("45ggEzakPJQ", "libSceNet", 1, "libSceNet", 1, 1, sceNetSocketClose);

    LIB_FUNCTION("BTUvkWzrP68", "libSceNet", 1, "libSceNet", 1, 1, sceNetAddrConfig6GetInfo);
    LIB_FUNCTION("3qG7UJy2Fq8", "libSceNet", 1, "libSceNet", 1, 1, sceNetAddrConfig6Start);
    LIB_FUNCTION("P+0ePpDfUAQ", "libSceNet", 1, "libSceNet", 1, 1, sceNetAddrConfig6Stop);
    LIB_FUNCTION("PcdLABhYga4", "libSceNet", 1, "libSceNet", 1, 1, sceNetAllocateAllRouteInfo);
    LIB_FUNCTION("xHq87H78dho", "libSceNet", 1, "libSceNet", 1, 1,
                 sceNetBandwidthControlGetDataTraffic);
    LIB_FUNCTION("c8IRpl4L74I", "libSceNet", 1, "libSceNet", 1, 1,
                 sceNetBandwidthControlGetDefaultParam);
    LIB_FUNCTION("b9Ft65tqvLk", "libSceNet", 1, "libSceNet", 1, 1,
                 sceNetBandwidthControlGetIfParam);
    LIB_FUNCTION("PDkapOwggRw", "libSceNet", 1, "libSceNet", 1, 1, sceNetBandwidthControlGetPolicy);
    LIB_FUNCTION("P4zZXE7bpsA", "libSceNet", 1, "libSceNet", 1, 1,
                 sceNetBandwidthControlSetDefaultParam);
    LIB_FUNCTION("g4DKkzV2qC4", "libSceNet", 1, "libSceNet", 1, 1,
                 sceNetBandwidthControlSetIfParam);
    LIB_FUNCTION("7Z1hhsEmkQU", "libSceNet", 1, "libSceNet", 1, 1, sceNetBandwidthControlSetPolicy);
    LIB_FUNCTION("eyLyLJrdEOU", "libSceNet", 1, "libSceNet", 1, 1, sceNetClearDnsCache);
    LIB_FUNCTION("Ea2NaVMQNO8", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigAddArp);
    LIB_FUNCTION("0g0qIuPN3ZQ", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigAddArpWithInterface);
    LIB_FUNCTION("ge7g15Sqhks", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigAddIfaddr);
    LIB_FUNCTION("FDHr4Iz7dQU", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigAddMRoute);
    LIB_FUNCTION("Cyjl1yzi1qY", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigAddRoute);
    LIB_FUNCTION("Bu+L5r1lKRg", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigAddRoute6);
    LIB_FUNCTION("wIGold7Lro0", "libSceNet", 1, "libSceNet", 1, 1,
                 sceNetConfigAddRouteWithInterface);
    LIB_FUNCTION("MzA1YrRE6rA", "libSceNet", 1, "libSceNet", 1, 1,
                 sceNetConfigCleanUpAllInterfaces);
    LIB_FUNCTION("HJt+4x-CnY0", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigDelArp);
    LIB_FUNCTION("xTcttXJ3Utg", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigDelArpWithInterface);
    LIB_FUNCTION("RuVwHEW6dM4", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigDelDefaultRoute);
    LIB_FUNCTION("UMlVCy7RX1s", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigDelDefaultRoute6);
    LIB_FUNCTION("0239JNsI6PE", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigDelIfaddr);
    LIB_FUNCTION("hvCXMwd45oc", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigDelIfaddr6);
    LIB_FUNCTION("5Yl1uuh5i-A", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigDelMRoute);
    LIB_FUNCTION("QO7+2E3cD-U", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigDelRoute);
    LIB_FUNCTION("4wDGvfhmkmk", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigDelRoute6);
    LIB_FUNCTION("3WzWV86AJ3w", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigDownInterface);
    LIB_FUNCTION("mOUkgTaSkJU", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigEtherGetLinkMode);
    LIB_FUNCTION("pF3Vy1iZ5bs", "libSceNet", 1, "libSceNet", 1, 1,
                 sceNetConfigEtherPostPlugInOutEvent);
    LIB_FUNCTION("QltDK6wWqF0", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigEtherSetLinkMode);
    LIB_FUNCTION("18KNgSvYx+Y", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigFlushRoute);
    LIB_FUNCTION("lFJb+BlPK1c", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigGetDefaultRoute);
    LIB_FUNCTION("mCLdiNIKtW0", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigGetDefaultRoute6);
    LIB_FUNCTION("ejwa0hWWhDs", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigGetIfaddr);
    LIB_FUNCTION("FU6NK4RHQVE", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigGetIfaddr6);
    LIB_FUNCTION("vbZLomImmEE", "libSceNet", 1, "libSceNet", 1, 1,
                 sceNetConfigRoutingShowRoutingConfig);
    LIB_FUNCTION("a6sS6iSE0IA", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigRoutingShowtCtlVar);
    LIB_FUNCTION("eszLdtIMfQE", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigRoutingStart);
    LIB_FUNCTION("toi8xxcSfJ0", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigRoutingStop);
    LIB_FUNCTION("EAl7xvi7nXg", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigSetDefaultRoute);
    LIB_FUNCTION("4zLOHbt3UFk", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigSetDefaultRoute6);
    LIB_FUNCTION("yaVAdLDxUj0", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigSetDefaultScope);
    LIB_FUNCTION("8Kh+1eidI3c", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigSetIfaddr);
    LIB_FUNCTION("QJbV3vfBQ8Q", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigSetIfaddr6);
    LIB_FUNCTION("POrSEl8zySw", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigSetIfaddr6WithFlags);
    LIB_FUNCTION("0sesmAYH3Lk", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigSetIfFlags);
    LIB_FUNCTION("uNTluLfYgS8", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigSetIfLinkLocalAddr6);
    LIB_FUNCTION("s31rYkpIMMQ", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigSetIfmtu);
    LIB_FUNCTION("tvdzQkm+UaY", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigUnsetIfFlags);
    LIB_FUNCTION("oGEBX0eXGFs", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigUpInterface);
    LIB_FUNCTION("6HNbayHPL7c", "libSceNet", 1, "libSceNet", 1, 1,
                 sceNetConfigUpInterfaceWithFlags);
    LIB_FUNCTION("6A6EweB3Dto", "libSceNet", 1, "libSceNet", 1, 1,
                 sceNetConfigWlanAdhocClearWakeOnWlan);
    LIB_FUNCTION("ZLdJyQJUMkM", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigWlanAdhocCreate);
    LIB_FUNCTION("Yr3UeApLWTY", "libSceNet", 1, "libSceNet", 1, 1,
                 sceNetConfigWlanAdhocGetWakeOnWlanInfo);
    LIB_FUNCTION("Xma8yHmV+TQ", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigWlanAdhocJoin);
    LIB_FUNCTION("K4o48GTNbSc", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigWlanAdhocLeave);
    LIB_FUNCTION("ZvKgNrrLCCQ", "libSceNet", 1, "libSceNet", 1, 1,
                 sceNetConfigWlanAdhocPspEmuClearWakeOnWlan);
    LIB_FUNCTION("1j4DZ5dXbeQ", "libSceNet", 1, "libSceNet", 1, 1,
                 sceNetConfigWlanAdhocPspEmuGetWakeOnWlanInfo);
    LIB_FUNCTION("C-+JPjaEhdA", "libSceNet", 1, "libSceNet", 1, 1,
                 sceNetConfigWlanAdhocPspEmuSetWakeOnWlan);
    LIB_FUNCTION("7xYdUWg1WdY", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigWlanAdhocScanJoin);
    LIB_FUNCTION("Q7ee2Uav5f8", "libSceNet", 1, "libSceNet", 1, 1,
                 sceNetConfigWlanAdhocSetExtInfoElement);
    LIB_FUNCTION("xaOTiuxIQNY", "libSceNet", 1, "libSceNet", 1, 1,
                 sceNetConfigWlanAdhocSetWakeOnWlan);
    LIB_FUNCTION("QlRJWya+dtE", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigWlanApStart);
    LIB_FUNCTION("6uYcvVjH7Ms", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigWlanApStop);
    LIB_FUNCTION("MDbg-oAj8Aw", "libSceNet", 1, "libSceNet", 1, 1,
                 sceNetConfigWlanBackgroundScanQuery);
    LIB_FUNCTION("cMA8f6jI6s0", "libSceNet", 1, "libSceNet", 1, 1,
                 sceNetConfigWlanBackgroundScanStart);
    LIB_FUNCTION("3T5aIe-7L84", "libSceNet", 1, "libSceNet", 1, 1,
                 sceNetConfigWlanBackgroundScanStop);
    LIB_FUNCTION("+3KMyS93TOs", "libSceNet", 1, "libSceNet", 1, 1,
                 sceNetConfigWlanDiagGetDeviceInfo);
    LIB_FUNCTION("9oiOWQ5FMws", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigWlanDiagSetAntenna);
    LIB_FUNCTION("fHr45B97n0U", "libSceNet", 1, "libSceNet", 1, 1,
                 sceNetConfigWlanDiagSetTxFixedRate);
    LIB_FUNCTION("PNDDxnqqtk4", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigWlanGetDeviceConfig);
    LIB_FUNCTION("Pkx0lwWVzmQ", "libSceNet", 1, "libSceNet", 1, 1,
                 sceNetConfigWlanInfraGetRssiInfo);
    LIB_FUNCTION("IkBCxG+o4Nk", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigWlanInfraLeave);
    LIB_FUNCTION("273-I-zD8+8", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigWlanInfraScanJoin);
    LIB_FUNCTION("-Mi5hNiWC4c", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigWlanScan);
    LIB_FUNCTION("U1q6DrPbY6k", "libSceNet", 1, "libSceNet", 1, 1, sceNetConfigWlanSetDeviceConfig);
    LIB_FUNCTION("lDTIbqNs0ps", "libSceNet", 1, "libSceNet", 1, 1, sceNetControl);
    LIB_FUNCTION("Q6T-zIblNqk", "libSceNet", 1, "libSceNet", 1, 1, sceNetDhcpdStart);
    LIB_FUNCTION("xwWm8jzrpeM", "libSceNet", 1, "libSceNet", 1, 1, sceNetDhcpdStop);
    LIB_FUNCTION("KhQxhlEslo0", "libSceNet", 1, "libSceNet", 1, 1, sceNetDhcpGetAutoipInfo);
    LIB_FUNCTION("ix4LWXd12F0", "libSceNet", 1, "libSceNet", 1, 1, sceNetDhcpGetInfo);
    LIB_FUNCTION("DrZuCQDnm3w", "libSceNet", 1, "libSceNet", 1, 1, sceNetDhcpGetInfoEx);
    LIB_FUNCTION("Wzv6dngR-DQ", "libSceNet", 1, "libSceNet", 1, 1, sceNetDhcpStart);
    LIB_FUNCTION("6AN7OlSMWk0", "libSceNet", 1, "libSceNet", 1, 1, sceNetDhcpStop);
    LIB_FUNCTION("+ezgWao0wo8", "libSceNet", 1, "libSceNet", 1, 1, sceNetDumpAbort);
    LIB_FUNCTION("bghgkeLKq1Q", "libSceNet", 1, "libSceNet", 1, 1, sceNetDumpCreate);
    LIB_FUNCTION("xZ54Il-u1vs", "libSceNet", 1, "libSceNet", 1, 1, sceNetDumpDestroy);
    LIB_FUNCTION("YWTpt45PxbI", "libSceNet", 1, "libSceNet", 1, 1, sceNetDumpRead);
    LIB_FUNCTION("TwjkDIPdZ1Q", "libSceNet", 1, "libSceNet", 1, 1, sceNetDuplicateIpStart);
    LIB_FUNCTION("QCbvCx9HL30", "libSceNet", 1, "libSceNet", 1, 1, sceNetDuplicateIpStop);
    LIB_FUNCTION("w21YgGGNtBk", "libSceNet", 1, "libSceNet", 1, 1, sceNetEpollAbort);
    LIB_FUNCTION("ZVw46bsasAk", "libSceNet", 1, "libSceNet", 1, 1, sceNetEpollControl);
    LIB_FUNCTION("SF47kB2MNTo", "libSceNet", 1, "libSceNet", 1, 1, sceNetEpollCreate);
    LIB_FUNCTION("Inp1lfL+Jdw", "libSceNet", 1, "libSceNet", 1, 1, sceNetEpollDestroy);
    LIB_FUNCTION("drjIbDbA7UQ", "libSceNet", 1, "libSceNet", 1, 1, sceNetEpollWait);
    LIB_FUNCTION("HQOwnfMGipQ", "libSceNet", 1, "libSceNet", 1, 1, sceNetErrnoLoc);
    LIB_FUNCTION("v6M4txecCuo", "libSceNet", 1, "libSceNet", 1, 1, sceNetEtherNtostr);
    LIB_FUNCTION("b-bFZvNV59I", "libSceNet", 1, "libSceNet", 1, 1, sceNetEtherStrton);
    LIB_FUNCTION("cWGGXoeZUzA", "libSceNet", 1, "libSceNet", 1, 1, sceNetEventCallbackCreate);
    LIB_FUNCTION("jzP0MoZpYnI", "libSceNet", 1, "libSceNet", 1, 1, sceNetEventCallbackDestroy);
    LIB_FUNCTION("tB3BB8AsrjU", "libSceNet", 1, "libSceNet", 1, 1, sceNetEventCallbackGetError);
    LIB_FUNCTION("5isaotjMWlA", "libSceNet", 1, "libSceNet", 1, 1, sceNetEventCallbackWaitCB);
    LIB_FUNCTION("2ee14ktE1lw", "libSceNet", 1, "libSceNet", 1, 1, sceNetFreeAllRouteInfo);
    LIB_FUNCTION("q8j9OSdnN1Y", "libSceNet", 1, "libSceNet", 1, 1, sceNetGetArpInfo);
    LIB_FUNCTION("wmoIm94hqik", "libSceNet", 1, "libSceNet", 1, 1, sceNetGetDns6Info);
    LIB_FUNCTION("nCL0NyZsd5A", "libSceNet", 1, "libSceNet", 1, 1, sceNetGetDnsInfo);
    LIB_FUNCTION("HoV-GJyx7YY", "libSceNet", 1, "libSceNet", 1, 1, sceNetGetIfList);
    LIB_FUNCTION("ahiOMqoYYMc", "libSceNet", 1, "libSceNet", 1, 1, sceNetGetIfListOnce);
    LIB_FUNCTION("0MT2l3uIX7c", "libSceNet", 1, "libSceNet", 1, 1, sceNetGetIfName);
    LIB_FUNCTION("5lrSEHdqyos", "libSceNet", 1, "libSceNet", 1, 1, sceNetGetIfnameNumList);
    LIB_FUNCTION("6Oc0bLsIYe0", "libSceNet", 1, "libSceNet", 1, 1, sceNetGetMacAddress);
    LIB_FUNCTION("rMyh97BU5pY", "libSceNet", 1, "libSceNet", 1, 1, sceNetGetMemoryPoolStats);
    LIB_FUNCTION("+S-2-jlpaBo", "libSceNet", 1, "libSceNet", 1, 1, sceNetGetNameToIndex);
    LIB_FUNCTION("G3O2j9f5z00", "libSceNet", 1, "libSceNet", 1, 1, sceNetGetRandom);
    LIB_FUNCTION("6Nx1hIQL9h8", "libSceNet", 1, "libSceNet", 1, 1, sceNetGetRouteInfo);
    LIB_FUNCTION("hLuXdjHnhiI", "libSceNet", 1, "libSceNet", 1, 1, sceNetGetSockInfo);
    LIB_FUNCTION("Cidi9Y65mP8", "libSceNet", 1, "libSceNet", 1, 1, sceNetGetSockInfo6);
    LIB_FUNCTION("GA5ZDaLtUBE", "libSceNet", 1, "libSceNet", 1, 1, sceNetGetStatisticsInfo);
    LIB_FUNCTION("9mIcUExH34w", "libSceNet", 1, "libSceNet", 1, 1, sceNetGetStatisticsInfoInternal);
    LIB_FUNCTION("p2vxsE2U3RQ", "libSceNet", 1, "libSceNet", 1, 1, sceNetGetSystemTime);
    LIB_FUNCTION("9T2pDF2Ryqg", "libSceNet", 1, "libSceNet", 1, 1, sceNetHtonl);
    LIB_FUNCTION("3CHi1K1wsCQ", "libSceNet", 1, "libSceNet", 1, 1, sceNetHtonll);
    LIB_FUNCTION("iWQWrwiSt8A", "libSceNet", 1, "libSceNet", 1, 1, sceNetHtons);
    LIB_FUNCTION("9vA2aW+CHuA", "libSceNet", 1, "libSceNet", 1, 1, sceNetInetNtop);
    LIB_FUNCTION("Eh+Vqkrrc00", "libSceNet", 1, "libSceNet", 1, 1, sceNetInetNtopWithScopeId);
    LIB_FUNCTION("8Kcp5d-q1Uo", "libSceNet", 1, "libSceNet", 1, 1, sceNetInetPton);
    LIB_FUNCTION("Xn2TA2QhxHc", "libSceNet", 1, "libSceNet", 1, 1, sceNetInetPtonEx);
    LIB_FUNCTION("b+LixqREH6A", "libSceNet", 1, "libSceNet", 1, 1, sceNetInetPtonWithScopeId);
    LIB_FUNCTION("cYW1ISGlOmo", "libSceNet", 1, "libSceNet", 1, 1, sceNetInfoDumpStart);
    LIB_FUNCTION("XfV-XBCuhDo", "libSceNet", 1, "libSceNet", 1, 1, sceNetInfoDumpStop);
    LIB_FUNCTION("Nlev7Lg8k3A", "libSceNet", 1, "libSceNet", 1, 1, sceNetInit);
    LIB_FUNCTION("6MojQ8uFHEI", "libSceNet", 1, "libSceNet", 1, 1, sceNetInitParam);
    LIB_FUNCTION("ghqRRVQxqKo", "libSceNet", 1, "libSceNet", 1, 1, sceNetIoctl);
    LIB_FUNCTION("HKIa-WH0AZ4", "libSceNet", 1, "libSceNet", 1, 1, sceNetMemoryAllocate);
    LIB_FUNCTION("221fvqVs+sQ", "libSceNet", 1, "libSceNet", 1, 1, sceNetMemoryFree);
    LIB_FUNCTION("pQGpHYopAIY", "libSceNet", 1, "libSceNet", 1, 1, sceNetNtohl);
    LIB_FUNCTION("tOrRi-v3AOM", "libSceNet", 1, "libSceNet", 1, 1, sceNetNtohll);
    LIB_FUNCTION("Rbvt+5Y2iEw", "libSceNet", 1, "libSceNet", 1, 1, sceNetNtohs);
    LIB_FUNCTION("dgJBaeJnGpo", "libSceNet", 1, "libSceNet", 1, 1, sceNetPoolCreate);
    LIB_FUNCTION("K7RlrTkI-mw", "libSceNet", 1, "libSceNet", 1, 1, sceNetPoolDestroy);
    LIB_FUNCTION("QGOqGPnk5a4", "libSceNet", 1, "libSceNet", 1, 1, sceNetPppoeStart);
    LIB_FUNCTION("FIV95WE1EuE", "libSceNet", 1, "libSceNet", 1, 1, sceNetPppoeStop);
    LIB_FUNCTION("AzqoBha7js4", "libSceNet", 1, "libSceNet", 1, 1, sceNetResolverAbort);
    LIB_FUNCTION("JQk8ck8vnPY", "libSceNet", 1, "libSceNet", 1, 1, sceNetResolverConnect);
    LIB_FUNCTION("bonnMiDoOZg", "libSceNet", 1, "libSceNet", 1, 1, sceNetResolverConnectAbort);
    LIB_FUNCTION("V5q6gvEJpw4", "libSceNet", 1, "libSceNet", 1, 1, sceNetResolverConnectCreate);
    LIB_FUNCTION("QFPjG6rqeZg", "libSceNet", 1, "libSceNet", 1, 1, sceNetResolverConnectDestroy);
    LIB_FUNCTION("C4UgDHHPvdw", "libSceNet", 1, "libSceNet", 1, 1, sceNetResolverCreate);
    LIB_FUNCTION("kJlYH5uMAWI", "libSceNet", 1, "libSceNet", 1, 1, sceNetResolverDestroy);
    LIB_FUNCTION("J5i3hiLJMPk", "libSceNet", 1, "libSceNet", 1, 1, sceNetResolverGetError);
    LIB_FUNCTION("Apb4YDxKsRI", "libSceNet", 1, "libSceNet", 1, 1, sceNetResolverStartAton);
    LIB_FUNCTION("zvzWA5IZMsg", "libSceNet", 1, "libSceNet", 1, 1, sceNetResolverStartAton6);
    LIB_FUNCTION("Nd91WaWmG2w", "libSceNet", 1, "libSceNet", 1, 1, sceNetResolverStartNtoa);
    LIB_FUNCTION("zl35YNs9jnI", "libSceNet", 1, "libSceNet", 1, 1, sceNetResolverStartNtoa6);
    LIB_FUNCTION("RCCY01Xd+58", "libSceNet", 1, "libSceNet", 1, 1,
                 sceNetResolverStartNtoaMultipleRecords);
    LIB_FUNCTION("sT4nBQKUPqM", "libSceNet", 1, "libSceNet", 1, 1,
                 sceNetResolverStartNtoaMultipleRecordsEx);
    LIB_FUNCTION("15Ywg-ZsSl0", "libSceNet", 1, "libSceNet", 1, 1, sceNetSetDns6Info);
    LIB_FUNCTION("E3oH1qsdqCA", "libSceNet", 1, "libSceNet", 1, 1, sceNetSetDns6InfoToKernel);
    LIB_FUNCTION("B-M6KjO8-+w", "libSceNet", 1, "libSceNet", 1, 1, sceNetSetDnsInfo);
    LIB_FUNCTION("8s+T0bJeyLQ", "libSceNet", 1, "libSceNet", 1, 1, sceNetSetDnsInfoToKernel);
    LIB_FUNCTION("k1V1djYpk7k", "libSceNet", 1, "libSceNet", 1, 1, sceNetShowIfconfig);
    LIB_FUNCTION("j6pkkO2zJtg", "libSceNet", 1, "libSceNet", 1, 1, sceNetShowIfconfigForBuffer);
    LIB_FUNCTION("E8dTcvQw3hg", "libSceNet", 1, "libSceNet", 1, 1, sceNetShowIfconfigWithMemory);
    LIB_FUNCTION("WxislcDAW5I", "libSceNet", 1, "libSceNet", 1, 1, sceNetShowNetstat);
    LIB_FUNCTION("rX30iWQqqzg", "libSceNet", 1, "libSceNet", 1, 1, sceNetShowNetstatEx);
    LIB_FUNCTION("vjwKTGa21f0", "libSceNet", 1, "libSceNet", 1, 1, sceNetShowNetstatExForBuffer);
    LIB_FUNCTION("mqoB+LN0pW8", "libSceNet", 1, "libSceNet", 1, 1, sceNetShowNetstatForBuffer);
    LIB_FUNCTION("H5WHYRfDkR0", "libSceNet", 1, "libSceNet", 1, 1, sceNetShowNetstatWithMemory);
    LIB_FUNCTION("tk0p0JmiBkM", "libSceNet", 1, "libSceNet", 1, 1, sceNetShowPolicy);
    LIB_FUNCTION("dbrSNEuZfXI", "libSceNet", 1, "libSceNet", 1, 1, sceNetShowPolicyWithMemory);
    LIB_FUNCTION("cEMX1VcPpQ8", "libSceNet", 1, "libSceNet", 1, 1, sceNetShowRoute);
    LIB_FUNCTION("fCa7-ihdRdc", "libSceNet", 1, "libSceNet", 1, 1, sceNetShowRoute6);
    LIB_FUNCTION("nTJqXsbSS1I", "libSceNet", 1, "libSceNet", 1, 1, sceNetShowRoute6ForBuffer);
    LIB_FUNCTION("TCZyE2YI1uM", "libSceNet", 1, "libSceNet", 1, 1, sceNetShowRoute6WithMemory);
    LIB_FUNCTION("n-IAZb7QB1Y", "libSceNet", 1, "libSceNet", 1, 1, sceNetShowRouteForBuffer);
    LIB_FUNCTION("0-XSSp1kEFM", "libSceNet", 1, "libSceNet", 1, 1, sceNetShowRouteWithMemory);
    LIB_FUNCTION("6AJE2jKg-c0", "libSceNet", 1, "libSceNet", 1, 1, sceNetSyncCreate);
    LIB_FUNCTION("atGfzCaXMak", "libSceNet", 1, "libSceNet", 1, 1, sceNetSyncDestroy);
    LIB_FUNCTION("sAleh-BoxLA", "libSceNet", 1, "libSceNet", 1, 1, sceNetSyncGet);
    LIB_FUNCTION("Z-8Jda650Vk", "libSceNet", 1, "libSceNet", 1, 1, sceNetSyncSignal);
    LIB_FUNCTION("NP5gxDeYhIM", "libSceNet", 1, "libSceNet", 1, 1, sceNetSyncWait);
    LIB_FUNCTION("3zRdT3O2Kxo", "libSceNet", 1, "libSceNet", 1, 1, sceNetSysctl);
    LIB_FUNCTION("cTGkc6-TBlI", "libSceNet", 1, "libSceNet", 1, 1, sceNetTerm);
    LIB_FUNCTION("j-Op3ibRJaQ", "libSceNet", 1, "libSceNet", 1, 1, sceNetThreadCreate);
    LIB_FUNCTION("KirVfZbqniw", "libSceNet", 1, "libSceNet", 1, 1, sceNetThreadExit);
    LIB_FUNCTION("pRbEzaV30qI", "libSceNet", 1, "libSceNet", 1, 1, sceNetThreadJoin);
    LIB_FUNCTION("bjrzRLFali0", "libSceNet", 1, "libSceNet", 1, 1, sceNetUsleep);
    LIB_FUNCTION("DnB6WJ91HGg", "libSceNet", 1, "libSceNet", 1, 1, Func_0E707A589F751C68);
    LIB_FUNCTION("JK1oZe4UysY", "libSceNetDebug", 1, "libSceNet", 1, 1, sceNetEmulationGet);
    LIB_FUNCTION("pfn3Fha1ydc", "libSceNetDebug", 1, "libSceNet", 1, 1, sceNetEmulationSet);
};

} // namespace Libraries::Net
