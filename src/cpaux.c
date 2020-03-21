#include "cpaux.h"

/* see http://www.faqs.org/rfcs/rfc1071.html */
uint16_t inet_checksum16(const void* buf, unsigned int len){
    uint32_t  u32buf = 0;
    uint16_t *u16arr;
    unsigned int u16len;

    u16arr = buf;
    u16len = len >> 1;
    
    for (;u16len--;){
        u32buf += u16arr[u16len];
    }
    if (len & 0x1){
        /* have odd bytes */
        u32buf += (uint32_t)(((uint8_t*)buf)[len - 1]);
    }

    /* add back the carry bits */
    u32buf  = (u32buf >> 16) + (u32buf & 0xFFFF);
    u32buf += (u32buf >> 16);

    return (uint16_t)((~u32buf) & 0xFFFF);
}
/* python code
def inet_checksum(data: bytes) -> int:
    u16_arr = array.array("H", data)
    chksum = 0
    for i in u16_arr:
        # x86 machine reads memory as LE, convert these numbers to BE first.
        i = socket.htons(i)
        chksum += (i & 0xFFFF)
    chksum =    (chksum >> 16) + (chksum & 0xFFFF)
    chksum +=   (chksum >> 16)
    return (~chksum) & 0xFFFF
*/