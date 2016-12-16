/*
author : WangBin
function : 无IP模式下发送UDP数据包
modify date : 
*/

#include <libnet.h>
#include <sys/types.h>

#include "senddata.h"

#define debug
/*将MAC地址转换为byte[]数组*/
int mac_str_to_bin( u_char *str, u_char *mac);

/*无IP模式下发送UDP数据包*/
int send_udp(char *dst_ipstr, char *src_ipstr, u_char *dst_mac_addr,
				char *cont_str, u_int16_t src_port, u_int16_t dst_port)
{
	libnet_t *handle; /* Libnet句柄 */
	int packet_size; /* 构造的数据包大小 */
	char *device = "br0"; /* 设备名字,也支持点十进制的IP地址,会自己找到匹配的设备 */
	char *src_ip_str = src_ipstr; /* 源IP地址字符串 */
	char *dst_ip_str = dst_ipstr; /* 目的IP地址字符串 */
	//char src_ip_str[255] = {0};	/* 源IP地址字符串 */
	//char dst_ip_str[255] = {0};	/* 目的IP地址字符串 */
	//strncpy(src_ip_str, src_ipstr, strlen(src_ipstr)+1);
	//strncpy(dst_ip_str, dst_ipstr, strlen(dst_ipstr)+1);
	
	#ifdef debug
		printf("srcip is:%s , dstip is:%s\n", src_ip_str,dst_ip_str);
	#endif
	
	/*
	*获得本地MAC地址，即源MAC
	*/
	FILE *fp;  
	u_char buffer[18];
	u_char src_mac[6];	/* 源MAC */
	
	fp = popen("cat /sys/class/net/br0/address","r");
	fgets((char*)buffer,sizeof((char*)buffer),fp);
	mac_str_to_bin(buffer,src_mac);  
	pclose(fp);

	#ifdef debug
		//printf("%s\n",buffer);  
		printf("Local_MAC : %2.2X-%2.2X-%2.2X-%2.2X-%2.2X-%2.2X\n", 
				src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);
	#endif

	/*
	*获取目的MAC地址
	*/
	u_char dst_mac[6]; /* 目的MAC */
	u_char mac[17];
	
	int count = 0;
	for ( ; count < 17; ++count)
	{
		*(mac + count) = *(dst_mac_addr + count);
		//printf("%c", mac[i]);
	}

	mac_str_to_bin(mac, dst_mac);
	
	#ifdef debug
		printf("Dst_MAC : %2.2X-%2.2X-%2.2X-%2.2X-%2.2X-%2.2X\n", 
				dst_mac[0],dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);
	#endif

	u_long dst_ip, src_ip; /* 网路序的目的IP和源IP */
	char error[LIBNET_ERRBUF_SIZE]; /* 出错信息 */
	libnet_ptag_t eth_tag, ip_tag, udp_tag; /* 各层build函数返回值 */
	u_short proto = IPPROTO_UDP; /* 传输层协议 */
	u_char payload[255] = {0}; /* 承载数据的数组，初值为空 */
	u_long payload_s = 0; /* 承载数据的长度，初值为0 */

	/* 把目的IP地址字符串转化成网络序 */
	dst_ip = libnet_name2addr4(handle, dst_ip_str, LIBNET_RESOLVE);
	/* 把源IP地址字符串转化成网络序 */
	src_ip = libnet_name2addr4(handle, src_ip_str, LIBNET_RESOLVE);

	/* 初始化Libnet */
	if ( (handle = libnet_init(LIBNET_LINK, device, error)) == NULL ) {
		#ifdef debug
			printf("libnet_init failure\n");
		#endif
		return (-1);
	};

	strncpy((char*)payload, cont_str, strlen(cont_str)+1); /* 构造负载的内容 */
	payload_s = strlen((char*)payload); /* 计算负载内容的长度 */

	udp_tag = libnet_build_udp(
			src_port, /* 源端口 */
			dst_port, /* 目的端口 */
			LIBNET_UDP_H + payload_s, /* 长度 */
			0, /* 校验和,0为libnet自动计算 */
			payload, /* 负载内容 */
			payload_s, /* 负载内容长度 */
			handle, /* libnet句柄 */
			0 /* 新建包 */
			);
	if (udp_tag == -1) {
		#ifdef debug
			printf("libnet_build_tcp failure\n");
		#endif
		return (-3);
	};

	/* 构造IP协议块，返回值是新生成的IP协议快的一个标记 */
	ip_tag = libnet_build_ipv4(
			LIBNET_IPV4_H + LIBNET_UDP_H + payload_s, /* IP协议块的总长*/
			0, /* tos */
			(u_short) libnet_get_prand(LIBNET_PRu16), /* id,随机产生0~65535 */
			0, /* frag 片偏移 */
			(u_int8_t)libnet_get_prand(LIBNET_PR8), /* ttl,随机产生0~255 */
			proto, /* 上层协议 */
			0, /* 校验和，此时为0，表示由Libnet自动计算 */
			src_ip, /* 源IP地址,网络序 */
			dst_ip, /* 目标IP地址,网络序 */
			NULL, /* 负载内容或为NULL */
			0, /* 负载内容的大小*/
			handle, /* Libnet句柄 */
			0 /* 协议块标记可修改或创建,0表示构造一个新的*/
			);
	if (ip_tag == -1) {
		#ifdef debug
			printf("libnet_build_ipv4 failure\n");
		#endif
		return (-4);
	};

	/* 构造一个以太网协议块,只能用于LIBNET_LINK */
	eth_tag = libnet_build_ethernet(
			dst_mac, /* 以太网目的地址 */
			src_mac, /* 以太网源地址 */
			ETHERTYPE_IP, /* 以太网上层协议类型，此时为IP类型 */
			NULL, /* 负载，这里为空 */ 
			0, /* 负载大小 */
			handle, /* Libnet句柄 */
			0 /* 协议块标记，0表示构造一个新的 */ 
			);
	if (eth_tag == -1) {
		#ifdef debug
			printf("libnet_build_ethernet failure\n");
		#endif
		return (-5);
	};

	packet_size = libnet_write(handle); /* 发送已经构造的数据包*/

	#ifdef debug
		printf("Send successfully!!!\n");
		printf("\n");
	#endif

	libnet_destroy(handle); /* 释放句柄 */

	return (0);
}

int mac_str_to_bin( u_char *str, u_char *mac)
{
    int i;
    u_char *s, *e;

    if ((mac == NULL) || (str == NULL))
    {
        return -1;
    }

    s = (u_char *) str;
    for (i = 0; i < 6; ++i)
    {
        mac[i] = s ? strtoul (s, &e, 16) : 0;
        if (s)
           s = (*e) ? e + 1 : e;
    }
    return 0;
}
