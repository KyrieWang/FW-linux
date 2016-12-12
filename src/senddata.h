/*
author : WangBin
function : Send_data接口
modify date : 
*/
#ifndef SENDDATA_H
#define SENDDATA_H

#include <sys/types.h>

extern int send_udp(char *dst_ipstr , char *src_ipstr , u_char *dst_mac_addr);	/*无IP模式下发送UDP数据包*/

#endif // !SENDDATA_H