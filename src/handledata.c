/*
author : WangBin
function : 
modify date : 
*/

#include <sys/stat.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <linux/sockios.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <errno.h>
#include <linux/netfilter_ipv4/ipt_ULOG.h>
#include <linux/netdevice.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <libnetfilter_log/linux_nfnetlink_log.h>
#include <libnfnetlink/libnfnetlink.h>

#include "handledata.h"
#include "senddata.h"
#include "get_ip.h"
#include "get_mac_by_ip.h"

#define MAX_MSG_SIZE 1024 /*接收缓冲区大小*/
#define LOG_CP_RANGE 1024 /*拷贝的数据包范围*/
#define debug

/*回调函数*/
int handle_packet(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg, struct nflog_data *nfa, void *data);

/*计算command长度*/
size_t str_len(char *str);

/*处理命令字符串*/
//char *cmd_handle(char *str , size_t length);

void handle_data()
{
	static int lb_nflog_fd;
	static struct nflog_handle *handle;
	static struct nflog_g_handle *group_handle;

	/*
	**nflog初始化
	*/
	handle = nflog_open();  /*打开nflog*/
	nflog_bind_pf(handle, AF_INET);  /*绑定地址族*/
	group_handle = nflog_bind_group(handle, 10);	/*绑定netlink组*/
	
	nflog_set_mode(group_handle, NFULNL_COPY_PACKET, LOG_CP_RANGE);		/*设置拷贝的数据包范围*/
	nflog_set_qthresh(group_handle, 1);		/*设置数据包缓存数量*/
	
	nflog_callback_register(group_handle, &handle_packet, NULL);		/*注册回掉函数handle_packet,收到数据包后调用handle_packet处理*/
	
	lb_nflog_fd = nflog_fd(handle);
	
	char buf[MAX_MSG_SIZE];  /*接收缓冲区*/

	/*
	**循环监听，接收、处理处理数据包
	*/
	while(1)
	{	
		int res = recv(lb_nflog_fd, buf, sizeof(buf),0);	/*接收一组数据包，存储在buf中，返回数据长度*/
		nflog_handle_packet(handle, buf, res);		/*由回调函数处理数据包*/
	}
}

int handle_packet(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg, struct nflog_data *nfa, void *data)
{
	#ifdef debug
		printf("*********starting processing data***********\n");
	#endif
		
	char *payload;
		
	nflog_get_payload(nfa, &payload);  /*获取IP数据包*/
	struct iphdr *iph = (struct iphdr *)payload;	/*iphdr指向IP数据包包头位置*/
	
	
	/*获得源IP地址*/
	struct in_addr src_addr;
	src_addr.s_addr = iph->saddr;
	char *src_ip = inet_ntoa(src_addr);

	size_t src_ip_len = strlen(src_ip);
	char src_ip_addr[src_ip_len + 1];
	strncpy(src_ip_addr, src_ip, src_ip_len + 1);
	src_ip_addr[src_ip_len] = '\0';
	
	#ifdef debug
		printf("src_addr:%s\n", src_ip_addr);
	#endif

	/*获得目的IP地址*/
	struct in_addr dst_addr;
	dst_addr.s_addr = iph->daddr;
	char *dst_ip_addr = inet_ntoa(dst_addr);

	#ifdef debug
		printf("dst_addr:%s\n", dst_ip_addr);
	#endif
	
	#ifdef debug
		printf("protocol is:\n");
	#endif
	
	/*
	**判断协议类型
	*/
	#ifdef debug
		switch(iph->protocol)
		{
    		case IPPROTO_TCP:printf("TCP\n");break;
			case IPPROTO_UDP:printf("UDP\n");break;
			case IPPROTO_ICMP:printf("ICMP\n");break;
			default : printf("unknown protocol\n");
		}
	#endif
		
	struct udphdr *udph;	
	udph = (struct udphdr *)((void *)iph+4*(iph->ihl));  /*udph指向udp数据包头*/
	char *selfh1 = (char *)((void *)udph + 8);  /*selfh指向自定义数据包包头，包头为3个字节*/
	char *selfh2 = (char *)((void *)udph + 9);
	char *selfh3 = (char *)((void *)udph + 10); 
	char *selfh4 = (char *)((void *)udph + 11); /*self4指向自定义数据包的数据内容*/

	/*防火墙规则配置*/
	if (iph->protocol == IPPROTO_UDP && ntohs(udph->dest) == 22222
								&& *selfh1 == 0x0f && *selfh2 == 0x0f && *selfh3 ==0x0d)
	{
		size_t maclen = str_len(selfh4);
		char mac[maclen + 1];
		strncpy(mac, selfh4, maclen+1);
		mac[maclen] = '\0';
		
		size_t cmdlen = str_len(selfh4);
		char cmd[cmdlen + 1];
		strncpy(cmd, selfh4, cmdlen+1);
		cmd[cmdlen] = '\0';

		#ifdef debug
			printf("cmd is :%s\n", cmd);
		#endif
		/*在Linux执行命令,添加防火墙规则*/
		int status = system(cmd);
		#ifdef debug
				printf("cmd execute successfully !!!\n");
		#endif
		if(!WIFSIGNALED(status))
		{
			char *confirm_info = "yes";
			send_udp(src_ip_addr, dst_ip_addr, (u_char *)mac, confirm_info, 30332, 30333);
			#ifdef debug
				printf("confirm yes !!!\n");
			#endif
		}
	}

	/*防火墙设备确认*/
	if (iph->protocol == IPPROTO_UDP && ntohs(udph->dest) == 33333
								&& *selfh1 == 0x0f && *selfh2 == 0x0e && *selfh3 ==0x0d)
	{
		size_t maclen = str_len(selfh4);
		char mac[maclen + 1];
		strncpy(mac, selfh4, maclen+1);
		mac[maclen] = '\0';
		
		#ifdef debug
			printf("mac is :%s\n", mac);
			printf("src_addr:%s\n", src_ip_addr);
			printf("dst_addr:%s\n", dst_ip_addr);
		#endif

		char src_ip_str[255] = {0};
		char dst_ip_str[255] = {0};
		strncpy(src_ip_str, src_ip_addr, strlen(src_ip_addr)+1);
		strncpy(dst_ip_str, dst_ip_addr, strlen(dst_ip_addr)+1);
		char *local_IP = get_ip();	//获取防火墙IP
		char dev_mac[128] = {0};
		get_mac_by_ip(dst_ip_str, dev_mac);	//获取受保护设备的mac地址

		#ifdef debug
			printf("after get_ip :\n");
			printf("src_addr:%s\n", src_ip_addr);
			printf("dst_addr:%s\n", dst_ip_addr);
			printf("dev_mac is %s\n", dev_mac);
		#endif
		
		char content[128];
		memset(content, '\0', sizeof(content));
		if(local_IP == NULL)
		{
			char *no_IP = "0.0.0.0&";
			strncpy(content, no_IP, strlen(no_IP));
			strncat(content, dev_mac, strlen(dev_mac));
			#ifdef debug
				printf("content is %s\n", content);
			#endif
			send_udp(src_ip_str, dst_ip_str, (u_char *)mac, content, 30330, 30331);
		}
		else
		{
			strncpy(content, local_IP, strlen(local_IP));
			strncat(content, "&", strlen("&"));
			strncat(content, dev_mac, strlen(dev_mac));
			#ifdef debug
				printf("content is %s\n", content);
			#endif
			send_udp(src_ip_str, dst_ip_str, (u_char *)mac, content, 30330, 30331);	/*发送存在该防火墙的确认消息给客户端*/
		}
	}
	return 0;
}

size_t str_len(char *str)
{
	int length;

	for (length = 0; *str++ != '!'; )
	{
		/* code */
		length += 1;
	}

	return length;
}