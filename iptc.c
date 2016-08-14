// COMPLETELY WORKING VERSION

#include <stdio.h>
#include <sys/errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libiptc/libiptc.h>
#include <linux/netfilter/xt_limit.h>
#include <linux/netfilter/xt_physdev.h>
#include <linux/netfilter/xt_dscp.h>
#include <linux/netfilter/xt_mark.h>
#include <linux/netfilter/xt_RATEEST.h>
#include <linux/netfilter/xt_rateest.h>
#include <linux/netfilter/xt_DSCP.h>
#include <linux/netfilter/xt_tcpudp.h>
#include <linux/netfilter/xt_physdev.h>
#include <linux/netfilter/x_tables.h>
#include <netinet/in.h>
#include <unistd.h>

enum
{
    XT_MARK_SET=0,
    XT_MARK_AND,
    XT_MARK_OR
};
  
//struct xt_mark_target_info_v1
//{
//    unsigned long mark;
//    __u8 mode;
//};

int main()
{
        struct ipt_entry *e = NULL;
        struct xtc_handle *h = iptc_init("mangle");
        int result = 0;
        if(!h) { printf( "error condition  %s\n", iptc_strerror(errno)); return -1;}

        unsigned int targetOffset =  XT_ALIGN(sizeof(struct ipt_entry)) +  XT_ALIGN(sizeof(struct ipt_entry_match)) +  XT_ALIGN(sizeof(struct xt_tcp));

        unsigned int totalLen = targetOffset + (XT_ALIGN(sizeof(struct xt_entry_target)) + XT_ALIGN(sizeof(struct xt_mark_tginfo2)));

        e = (struct ipt_entry *)calloc(1, totalLen);
        if(e == NULL)
        {
                printf("calloc failure :%s\n", strerror(errno));
                return -1;
        }

        e->target_offset = targetOffset;
        e->next_offset = totalLen;
        e->ip.proto = 6;
        e->ip.invflags = 0x0;

        struct ipt_entry_match *matchTcp = (struct ipt_entry_match *) ((void *)e->elems + 0);
        struct xt_tcp *tcpInfo;

        struct xt_entry_target *dscpTarget = (struct xt_entry_target *) ((void *)e->elems + XT_ALIGN(sizeof(struct ipt_entry_match)) + XT_ALIGN(sizeof(struct xt_tcp)));
        struct xt_mark_tginfo2 *dscpInfo;

        matchTcp->u.match_size = XT_ALIGN(sizeof(struct ipt_entry_match)) + XT_ALIGN(sizeof(struct xt_tcp));
        strcpy(matchTcp->u.user.name, "tcp");
        tcpInfo = (struct xt_tcp*)matchTcp->data;
        tcpInfo->spts[0] = 0x0;
        tcpInfo->spts[1] = 0xFFFF;
        tcpInfo->dpts[0] = 80;
        tcpInfo->dpts[1] = 80;
        tcpInfo->invflags = 0x0000;

        dscpTarget->u.target_size = (XT_ALIGN(sizeof(struct xt_entry_target)) + XT_ALIGN(sizeof(struct xt_mark_tginfo2)));
        strcpy(dscpTarget->u.user.name,"MARK");
        dscpTarget->u.user.revision = 2;
        dscpInfo = (struct xt_mark_tginfo2 *)dscpTarget->data;
        dscpInfo->mark =  1;
        dscpInfo->mask = 0;

        int x = iptc_append_entry("OUTPUT", e, h);
        if (!x)
        {
                printf("iptc_append_entry::Error insert/append entry: %s\n", iptc_strerror(errno));
                result = -1;
                goto end;
        }

        int y = iptc_commit(h);
        if (!y)
        {
                printf("iptc_commit::Error commit: %s\n", iptc_strerror(errno));
                result = -1;
        }

        end:
            free(e);
            iptc_free(h);
            return result;
}
