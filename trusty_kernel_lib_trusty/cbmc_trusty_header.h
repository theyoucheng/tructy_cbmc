
#include <string.h>

//#ifndef _CBMC_TRUSTY_HEADER_H_
//#define _CBMC_TRUSTY_HEADER_H_

#define unlikely(x)     (x)

#define likely(x)     (x)

status_t copy_from_user(void *kdest, user_addr_t usrc, size_t len)
{
        //return NO_ERROR; //arch_copy_from_user(kdest, usrc, len);
        //return arch_copy_from_user(kdest, usrc, len);
        return memcpy(kdest, usrc, len);
}

status_t copy_to_user(user_addr_t udest, const void *ksrc, size_t len)
{
        //return NO_ERROR; //arch_copy_to_user(udest, ksrc, len);
        //return arch_copy_to_user(udest, ksrc, len);
        return memcpy(udest, ksrc, len);
}

long sys_port_create(user_addr_t path,
                               uint32_t num_recv_bufs,
                               uint32_t recv_buf_size,
                               uint32_t flags);

//long sys_connect(user_addr_t path, uint32_t flags);

//#endif
