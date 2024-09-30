#ifndef __SDTL_TUN_
#define __SDTL_TUN_ 1

#if defined(__APPLE__)

extern int open_utun();
extern char *get_utun_name(int fd);

#elif defined(__linux__)
extern char *alloc_ifname();
extern tun_alloc(char *dev);

#endif

extern char *sys_error();

#endif 