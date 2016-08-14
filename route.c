// COMPLETELY WORKING VERSION

#include <stdio.h>
#include <sys/errno.h>
#include <stdlib.h>
#include <string.h>
#include <libiptc/libiptc.h>
#include <linux/netfilter/xt_mark.h>
#include <linux/netfilter/x_tables.h>
#include <netinet/in.h>
#include <linux/route.h>
#include <unistd.h>

int setDefGateway(const char * deviceName,const char * defGateway)
{
int sockfd;
struct rtentry rm;
struct sockaddr_in ic_gateway ;// Gateway IP address
int err;

sockfd = socket(AF_INET, SOCK_DGRAM, 0);
if (sockfd == -1)
{
printf("socket is -1\n");
return -1;
}

memset(&rm, 0, sizeof(rm));


ic_gateway.sin_family = AF_INET;
ic_gateway.sin_addr.s_addr = inet_addr(defGateway);
ic_gateway.sin_port = 0;

(( struct sockaddr_in*)&rm.rt_dst)->sin_family = AF_INET;
(( struct sockaddr_in*)&rm.rt_dst)->sin_addr.s_addr = 0;
(( struct sockaddr_in*)&rm.rt_dst)->sin_port = 0;

(( struct sockaddr_in*)&rm.rt_genmask)->sin_family = AF_INET;
(( struct sockaddr_in*)&rm.rt_genmask)->sin_addr.s_addr = 0;
(( struct sockaddr_in*)&rm.rt_genmask)->sin_port = 0;

memcpy((void *) &rm.rt_gateway, &ic_gateway, sizeof(ic_gateway));
rm.rt_flags = RTF_UP | RTF_GATEWAY;
if ((err = ioctl(sockfd, SIOCADDRT, &rm)) < 0)
{
printf("SIOCADDRT failed , ret->%d\n",err);
return -1;
}
return 0;
}

int main()
{
    setDefGateway("wlan0", "192.168.43.1");
}
