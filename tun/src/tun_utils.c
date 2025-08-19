// Build:  gcc -O2 -Wall -Wextra -o tun_example tun_example.c
// Usage:  sudo ./tun_example <name> <ip/cidr> [mtu]
// Example: sudo ./tun_example tun0 10.0.0.1/24 1400
// Notes:   Requires CAP_NET_ADMIN (root).
//          This creates a TUN interface, assigns IPv4, netmask, MTU, and brings it UP.
//          Then it prints any IP packets received from the kernel (via the TUN fd).

#include "tun_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include "../../logger/src/logger.h"

int tun_create(char *ifname, size_t ifname_len) {
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        LOG_ERROR("open(/dev/net/tun): %s", strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (ifname && *ifname) {
        memset(ifr.ifr_name, 0, sizeof(ifr.ifr_name));
        size_t len = strnlen(ifname, IFNAMSIZ - 1);
        memcpy(ifr.ifr_name, ifname, len);
        // ifr.ifr_name is already zeroed
    }

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        LOG_ERROR("ioctl(TUNSETIFF): %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (ifname && ifname_len > 0) {
        size_t len = strnlen(ifr.ifr_name, IFNAMSIZ - 1);
        if (len >= ifname_len) len = ifname_len - 1;
        memcpy(ifname, ifr.ifr_name, len);
        ifname[len] = '\0';
    }

    return fd;
}

int if_set_flags(const char *ifname, short flags_mask, int set) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { LOG_ERROR("socket: %s", strerror(errno)); return -1; }

    struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
    memset(ifr.ifr_name, 0, sizeof(ifr.ifr_name));
    size_t len = strnlen(ifname, IFNAMSIZ - 1);
    memcpy(ifr.ifr_name, ifname, len);

    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) { LOG_ERROR("SIOCGIFFLAGS: %s", strerror(errno)); close(s); return -1; }
    if (set) { ifr.ifr_flags |= flags_mask; } else { ifr.ifr_flags &= ~flags_mask; }
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) { LOG_ERROR("SIOCSIFFLAGS: %s", strerror(errno)); close(s); return -1; }

    close(s); return 0;
}

int if_set_mtu(const char *ifname, int mtu) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { LOG_ERROR("socket: %s", strerror(errno)); return -1; }
    struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
    memset(ifr.ifr_name, 0, sizeof(ifr.ifr_name));
    size_t len = strnlen(ifname, IFNAMSIZ - 1);
    memcpy(ifr.ifr_name, ifname, len);
    ifr.ifr_mtu = mtu;
    if (ioctl(s, SIOCSIFMTU, &ifr) < 0) { LOG_ERROR("SIOCSIFMTU: %s", strerror(errno)); close(s); return -1; }
    close(s); return 0;
}

int if_set_addr_netmask(const char *ifname, const char *ip_str, const char *mask_str) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { LOG_ERROR("socket: %s", strerror(errno)); return -1; }

    struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
    memset(ifr.ifr_name, 0, sizeof(ifr.ifr_name));
    size_t len = strnlen(ifname, IFNAMSIZ - 1);
    memcpy(ifr.ifr_name, ifname, len);

    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip_str, &addr.sin_addr) != 1) {
        LOG_ERROR("invalid ip: %s", ip_str);
        close(s); return -1;
    }
    memcpy(&ifr.ifr_addr, &addr, sizeof(addr));
    if (ioctl(s, SIOCSIFADDR, &ifr) < 0) { LOG_ERROR("SIOCSIFADDR: %s", strerror(errno)); close(s); return -1; }

    memset(&ifr, 0, sizeof(ifr));
    memset(ifr.ifr_name, 0, sizeof(ifr.ifr_name));
    memcpy(ifr.ifr_name, ifname, len);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, mask_str, &addr.sin_addr) != 1) {
        LOG_ERROR("invalid netmask: %s", mask_str);
        close(s); return -1;
    }
    memcpy(&ifr.ifr_netmask, &addr, sizeof(addr));
    if (ioctl(s, SIOCSIFNETMASK, &ifr) < 0) { LOG_ERROR("SIOCSIFNETMASK: %s", strerror(errno)); close(s); return -1; }

    close(s); return 0;
}

void cidr_to_addr_mask(const char *cidr, char *ip_out, size_t ip_out_len, char *mask_out, size_t mask_out_len) {
    // cidr like 10.0.0.1/24
    char tmp[64]; 
    snprintf(tmp, sizeof(tmp), "%s", cidr);
    char *slash = strchr(tmp, '/');
    if (!slash) {
        size_t len = strnlen(tmp, ip_out_len - 1);
        memcpy(ip_out, tmp, len);
        ip_out[len] = '\0';
        strncpy(mask_out, "255.255.255.255", mask_out_len - 1);
        mask_out[mask_out_len - 1] = '\0';
        return;
    }
    *slash = '\0';
    int bits = atoi(slash + 1);
    if (bits < 0) {
        bits = 0;
    }
    if (bits > 32) {
        bits = 32;
    }
    uint32_t mask = bits == 0 ? 0 : htonl(0xFFFFFFFFu << (32 - bits));
    struct in_addr m; m.s_addr = mask;
    size_t len = strnlen(tmp, ip_out_len - 1);
    memcpy(ip_out, tmp, len);
    ip_out[len] = '\0';
    strncpy(mask_out, inet_ntoa(m), mask_out_len - 1);
    mask_out[mask_out_len - 1] = '\0';
}

ssize_t tun_read(int fd, void *buf, size_t len) {
    ssize_t n = read(fd, buf, len);
    if (n < 0) {
        if (errno == EINTR) return 0; // interrupted by signal, no error
        LOG_ERROR("tun_read: %s", strerror(errno));
        return -1;
    }
    return n;
}

ssize_t tun_write(int fd, const void *buf, size_t len) {
    ssize_t n = write(fd, buf, len);
    if (n < 0) {
        if (errno == EINTR) return 0;
        LOG_ERROR("tun_write: %s", strerror(errno));
        return -1;
    }
    return n;
}
