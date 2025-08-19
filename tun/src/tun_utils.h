#ifndef TUN_UTILS_H
#define TUN_UTILS_H

#include <stddef.h>
#include <sys/types.h> // for ssize_t
#include <net/if.h> // for IFNAMSIZ

#ifndef IFNAMSIZ
#define IFNAMSIZ IF_NAMESIZE
#endif

#ifdef __cplusplus
extern "C" {
#endif

int tun_create(char *ifname, size_t ifname_len);
int if_set_flags(const char *ifname, short flags_mask, int set);
int if_set_mtu(const char *ifname, int mtu);
int if_set_addr_netmask(const char *ifname, const char *ip_str, const char *mask_str);
void cidr_to_addr_mask(const char *cidr, char *ip_out, size_t ip_out_len, char *mask_out, size_t mask_out_len);
ssize_t tun_read(int fd, void *buf, size_t len);
ssize_t tun_write(int fd, const void *buf, size_t len);

typedef struct {
    int  fd;                 // /dev/net/tun fd
    char ifname[IFNAMSIZ];   // actual interface name (e.g., "tun0")
    int  mtu;                // configured MTU
} tun_handle_t;

#ifdef __cplusplus
}
#endif

#endif // TUN_UTILS_H
