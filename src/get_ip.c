#include <stdio.h>  
#include <stdlib.h>  
#include <unistd.h>  
#include <string.h>  
#include <sys/types.h>  
#include <arpa/inet.h>  
#include <net/if.h>  
#include <string.h>  
#include <signal.h>  
#include <sys/wait.h>  
#include <sys/ioctl.h>

#include "get_ip.h"

#define ETH_NAME "br0"

char *get_ip()
{
    int sock;  
    struct sockaddr_in sin;  
    struct ifreq ifr;  
    char *temp_ip = NULL;  
      
    sock = socket(AF_INET, SOCK_DGRAM, 0);  
    if (sock == -1)  
    {  
        perror("socket");  
        return NULL;                  
    }  
    strncpy(ifr.ifr_name, ETH_NAME, IFNAMSIZ-1);  
    ifr.ifr_name[IFNAMSIZ - 1] = 0;  
      
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)  
    {  
        perror("ioctl");  
        return NULL;  
    }  
  
    memcpy(&sin, &ifr.ifr_addr, sizeof(sin));  
    temp_ip = inet_ntoa(sin.sin_addr);   
    //fprintf(stdout, "eth0: %s\n", temp_ip);
    return temp_ip;
}