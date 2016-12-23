#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "get_mac_by_ip.h"

//#define debug

void get_mac_by_ip(char *dev_ip, char *dev_mac)
{
    FILE *stream;
    char buf[1024];
    char ping_cmd[128];
    char arp_cmd[128];
    char mac[128];

    strcpy(ping_cmd, "ping -c 1 ");
    strncat(ping_cmd, dev_ip, strlen(dev_ip));
    strcpy(arp_cmd, "arp ");
    strncat(arp_cmd, dev_ip, strlen(dev_ip));
    memset(buf, '\0',sizeof(buf));
    memset(dev_mac, '\0',sizeof(dev_mac));

    system(ping_cmd);
    stream = popen(arp_cmd, "r");
    size_t num = fread(buf, sizeof(char), sizeof(buf), stream);
    pclose(stream);
    
    if(num != 0)
    {
        #ifdef debug
            printf("arp output is :\n");
            printf("%s\n",buf);
        #endif

        char *ans = strchr(buf, ':');
        if(ans != NULL)
        {
            strncpy(dev_mac, ans-2, 17*sizeof(size_t));
            dev_mac[17] = '\0';
            
            #ifdef debug
                printf("mac is %s\n", dev_mac);
            #endif
        }
        return mac;
    }
}
/*
Address                  HWtype  HWaddress           Flags Mask            Iface
172.16.10.1              ether   f0:bf:97:e2:58:fe   C                     br0
*/