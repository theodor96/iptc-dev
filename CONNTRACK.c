#include <stdio.h>
#include <sys/errno.h>
#include <stdlib.h>
#include <string.h>
#include <libiptc/libiptc.h>
#include <linux/netfilter/xt_mark.h>
#include <linux/netfilter/xt_physdev.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/nf_nat.h>
#include <netinet/in.h>
#include <unistd.h>
#include <linux/netfilter/xt_conntrack.h>
#include <linux/netfilter/nf_conntrack_common.h>

int main()
{
        struct xtc_handle *h = iptc_init("filter");
        int result = 0;
        if(!h) { printf( "error condition  %s\n", iptc_strerror(errno)); return -1;}

        unsigned int targetOffset =  XT_ALIGN(sizeof(struct ipt_entry)) + XT_ALIGN(sizeof(struct xt_entry_match)) + XT_ALIGN(sizeof(struct xt_conntrack_mtinfo3));

        unsigned int totalLen = targetOffset + XT_ALIGN(sizeof(struct xt_standard_target));

        struct ipt_entry* e = (struct ipt_entry *)calloc(1, totalLen);
        if(e == NULL)
        {
                printf("calloc failure :%s\n", strerror(errno));
                return -1;
        }

        e->target_offset = targetOffset;
        e->next_offset = totalLen;
		
		struct xt_entry_match* match = (struct xt_entry_match*) e->elems;
		
		match->u.match_size = XT_ALIGN(sizeof(struct xt_entry_match)) + XT_ALIGN(sizeof(struct xt_conntrack_mtinfo3));
		strcpy(match->u.user.name, "conntrack");
		match->u.user.revision = 3;

		struct xt_conntrack_mtinfo3* conntrack = (struct xt_conntrack_mtinfo3  *) match->data;

		
		conntrack->match_flags |= XT_CONNTRACK_STATE;
		conntrack->state_mask |= XT_CONNTRACK_STATE_BIT(IP_CT_ESTABLISHED);
		conntrack->state_mask |= XT_CONNTRACK_STATE_BIT(IP_CT_RELATED);


        struct xt_standard_target* target = (struct xt_standard_target  *) (e->elems + XT_ALIGN(sizeof(struct xt_entry_match)) + XT_ALIGN(sizeof(struct xt_conntrack_mtinfo3)));
        target->target.u.target_size = XT_ALIGN(sizeof(struct xt_standard_target));
        strcpy(target->target.u.user.name, "RETURN");
		target->target.u.user.revision = 0;
		target->verdict = NF_REPEAT ;	
		
        int x = iptc_append_entry("INPUT", e, h);
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
