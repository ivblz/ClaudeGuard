/*
 * Copyright (c) 2007-2024 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

/*	$apfw: git commit b6bf13f8321283cd7ee82b1795e86506084b1b95 $ */
/*	$OpenBSD: pfvar.h,v 1.259 2007/12/02 12:08:04 pascoe Exp $ */

/*
 * Copyright (c) 2001 Daniel Hartmeier
 * NAT64 - Copyright (c) 2010 Viagenie Inc. (http://www.viagenie.ca)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef CLAUDEGUARD_PF_ABI_H
#define CLAUDEGUARD_PF_ABI_H
/* Minimal userspace ABI extract from Apple's bsd/net/pfvar.h.
 * Source: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pfvar.h
 * Download SHA256: aeaaa90c761577247bfa0328bd4765512f787f5af9a56b9bb530030c90a692c9
 * Only definitions needed for ticket-checked, single-rule operations remain.
 * This private ABI is checked by a read-only ioctl before any mutation.
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
enum    { PF_INOUT, PF_IN, PF_OUT };
enum    { PF_PASS, PF_DROP, PF_SCRUB, PF_NOSCRUB, PF_NAT, PF_NONAT,
	  PF_BINAT, PF_NOBINAT, PF_RDR, PF_NORDR, PF_SYNPROXY_DROP,
	  PF_DUMMYNET, PF_NODUMMYNET, PF_NAT64, PF_NONAT64 };
enum    { PF_RULESET_SCRUB, PF_RULESET_FILTER, PF_RULESET_NAT,
	  PF_RULESET_BINAT, PF_RULESET_RDR, PF_RULESET_DUMMYNET,
	  PF_RULESET_MAX };
enum    { PF_OP_NONE, PF_OP_IRG, PF_OP_EQ, PF_OP_NE, PF_OP_LT,
	  PF_OP_LE, PF_OP_GT, PF_OP_GE, PF_OP_XRG, PF_OP_RRG };
enum    { PF_DEBUG_NONE, PF_DEBUG_URGENT, PF_DEBUG_MISC, PF_DEBUG_NOISY };
enum    { PF_CHANGE_NONE, PF_CHANGE_ADD_HEAD, PF_CHANGE_ADD_TAIL,
	  PF_CHANGE_ADD_BEFORE, PF_CHANGE_ADD_AFTER,
	  PF_CHANGE_REMOVE, PF_CHANGE_GET_TICKET };
enum    { PF_GET_NONE, PF_GET_CLR_CNTR };

/*
 * Note about PFTM_*: real indices into pf_rule.timeout[] come before
 * PFTM_MAX, special cases afterwards. See pf_state_expires().
 */
enum    { PFTM_TCP_FIRST_PACKET, PFTM_TCP_OPENING, PFTM_TCP_ESTABLISHED,
	  PFTM_TCP_CLOSING, PFTM_TCP_FIN_WAIT, PFTM_TCP_CLOSED,
	  PFTM_UDP_FIRST_PACKET, PFTM_UDP_SINGLE, PFTM_UDP_MULTIPLE,
	  PFTM_ICMP_FIRST_PACKET, PFTM_ICMP_ERROR_REPLY,
	  PFTM_GREv1_FIRST_PACKET, PFTM_GREv1_INITIATING,
	  PFTM_GREv1_ESTABLISHED, PFTM_ESP_FIRST_PACKET, PFTM_ESP_INITIATING,
	  PFTM_ESP_ESTABLISHED, PFTM_OTHER_FIRST_PACKET, PFTM_OTHER_SINGLE,
	  PFTM_OTHER_MULTIPLE, PFTM_FRAG, PFTM_INTERVAL,
	  PFTM_ADAPTIVE_START, PFTM_ADAPTIVE_END, PFTM_SRC_NODE,
	  PFTM_TS_DIFF, PFTM_MAX, PFTM_PURGE, PFTM_UNLINKED };

struct pf_addr {
	union {
		struct in_addr          _v4addr;
		struct in6_addr         _v6addr;
		u_int8_t                _addr8[16];
		u_int16_t               _addr16[8];
		u_int32_t               _addr32[4];
	} pfa;              /* 128-bit address */
#define v4addr  pfa._v4addr
#define v6addr  pfa._v6addr
#define addr8   pfa._addr8
#define addr16  pfa._addr16
#define addr32  pfa._addr32
};

#define PF_TABLE_NAME_SIZE       32

#define PFI_AFLAG_NETWORK       0x01
#define PFI_AFLAG_BROADCAST     0x02
#define PFI_AFLAG_PEER          0x04
#define PFI_AFLAG_MODEMASK      0x07
#define PFI_AFLAG_NOALIAS       0x08

#ifndef RTLABEL_LEN
#define RTLABEL_LEN 32
#endif

struct pf_addr_wrap {
	union {
		struct {
			struct pf_addr           addr;
			struct pf_addr           mask;
		}                        a;
		char                     ifname[IFNAMSIZ];
		char                     tblname[PF_TABLE_NAME_SIZE];
		char                     rtlabelname[RTLABEL_LEN];
		u_int32_t                rtlabel;
	}                        v;
	union {
#ifdef KERNEL
		struct pfi_dynaddr      *dyn    __attribute__((aligned(8)));
		struct pfr_ktable       *tbl    __attribute__((aligned(8)));
#else /* !KERNEL */
		void                    *dyn    __attribute__((aligned(8)));
		void                    *tbl    __attribute__((aligned(8)));
#endif /* !KERNEL */
		int                      dyncnt __attribute__((aligned(8)));
		int                      tblcnt __attribute__((aligned(8)));
	}                        p __attribute__((aligned(8)));
	u_int8_t                 type;          /* PF_ADDR_* */
	u_int8_t                 iflags;        /* PFI_AFLAG_* */
};

struct pf_port_range {
	u_int16_t                       port[2];
	u_int8_t                        op;
};

union pf_rule_xport {
	struct pf_port_range    range;
	u_int16_t               call_id;
	u_int32_t               spi;
};

struct pf_rule_uid {
	uid_t            uid[2];
	u_int8_t         op;
	u_int8_t         _pad[3];
};

struct pf_rule_gid {
	uid_t            gid[2];
	u_int8_t         op;
	u_int8_t         _pad[3];
};

struct pf_rule_addr {
	struct pf_addr_wrap      addr;
	union pf_rule_xport      xport;
	u_int8_t                 neg;
};

struct pf_pooladdr {
	struct pf_addr_wrap              addr;
	TAILQ_ENTRY(pf_pooladdr)         entries;
#if !defined(__LP64__)
	u_int32_t                        _pad[2];
#endif /* !__LP64__ */
	char                             ifname[IFNAMSIZ];
#ifdef KERNEL
	struct pfi_kif                  *kif    __attribute__((aligned(8)));
#else /* !KERNEL */
	void                            *kif    __attribute__((aligned(8)));
#endif /* !KERNEL */
};

TAILQ_HEAD(pf_palist, pf_pooladdr);

struct pf_poolhashkey {
	union {
		u_int8_t                key8[16];
		u_int16_t               key16[8];
		u_int32_t               key32[4];
	} pfk;              /* 128-bit hash key */
#define key8    pfk.key8
#define key16   pfk.key16
#define key32   pfk.key32
};

struct pf_pool {
	struct pf_palist         list;
#if !defined(__LP64__)
	u_int32_t                _pad[2];
#endif /* !__LP64__ */
#ifdef KERNEL
	struct pf_pooladdr      *cur            __attribute__((aligned(8)));
#else /* !KERNEL */
	void                    *cur            __attribute__((aligned(8)));
#endif /* !KERNEL */
	struct pf_poolhashkey    key            __attribute__((aligned(8)));
	struct pf_addr           counter;
	int                      tblidx;
	u_int16_t                proxy_port[2];
	u_int8_t                 port_op;
	u_int8_t                 opts;
	sa_family_t              af;
};


/* A packed Operating System description for fingerprinting */
typedef u_int32_t pf_osfp_t;
union pf_rule_ptr {
	struct pf_rule          *ptr            __attribute__((aligned(8)));
	u_int32_t                nr             __attribute__((aligned(8)));
} __attribute__((aligned(8)));

#define PF_ANCHOR_NAME_SIZE      64

struct pf_rule {
	struct pf_rule_addr      src;
	struct pf_rule_addr      dst;
#define PF_SKIP_IFP             0
#define PF_SKIP_DIR             1
#define PF_SKIP_AF              2
#define PF_SKIP_PROTO           3
#define PF_SKIP_SRC_ADDR        4
#define PF_SKIP_SRC_PORT        5
#define PF_SKIP_DST_ADDR        6
#define PF_SKIP_DST_PORT        7
#define PF_SKIP_COUNT           8
	union pf_rule_ptr        skip[PF_SKIP_COUNT];
#define PF_RULE_LABEL_SIZE       64
	char                     label[PF_RULE_LABEL_SIZE];
#define PF_QNAME_SIZE            64
	char                     ifname[IFNAMSIZ];
	char                     qname[PF_QNAME_SIZE];
	char                     pqname[PF_QNAME_SIZE];
#define PF_TAG_NAME_SIZE         64
	char                     tagname[PF_TAG_NAME_SIZE];
	char                     match_tagname[PF_TAG_NAME_SIZE];

	char                     overload_tblname[PF_TABLE_NAME_SIZE];

	TAILQ_ENTRY(pf_rule)     entries;
#if !defined(__LP64__)
	u_int32_t                _pad[2];
#endif /* !__LP64__ */
	struct pf_pool           rpool;

	u_int64_t                evaluations;
	u_int64_t                packets[2];
	u_int64_t                bytes[2];

	u_int64_t                ticket;
#define PF_OWNER_NAME_SIZE       64
	char                     owner[PF_OWNER_NAME_SIZE];
	u_int32_t                priority;

#ifdef KERNEL
	struct pfi_kif          *kif            __attribute__((aligned(8)));
#else /* !KERNEL */
	void                    *kif            __attribute__((aligned(8)));
#endif /* !KERNEL */
	struct pf_anchor        *anchor         __attribute__((aligned(8)));
#ifdef KERNEL
	struct pfr_ktable       *overload_tbl   __attribute__((aligned(8)));
#else /* !KERNEL */
	void                    *overload_tbl   __attribute__((aligned(8)));
#endif /* !KERNEL */

	pf_osfp_t                os_fingerprint __attribute__((aligned(8)));

	unsigned int             rtableid;
	u_int32_t                timeout[PFTM_MAX];
	u_int32_t                states;
	u_int32_t                max_states;
	u_int32_t                src_nodes;
	u_int32_t                max_src_nodes;
	u_int32_t                max_src_states;
	u_int32_t                max_src_conn;
	struct {
		u_int32_t               limit;
		u_int32_t               seconds;
	}                        max_src_conn_rate;
	u_int32_t                qid;
	u_int32_t                pqid;
	u_int32_t                rt_listid;
	u_int32_t                nr;
	u_int32_t                prob;
	uid_t                    cuid;
	pid_t                    cpid;

	u_int16_t                return_icmp;
	u_int16_t                return_icmp6;
	u_int16_t                max_mss;
	u_int16_t                tag;
	u_int16_t                match_tag;

	struct pf_rule_uid       uid;
	struct pf_rule_gid       gid;

	u_int32_t                rule_flag;
	u_int8_t                 action;
	u_int8_t                 direction;
	u_int8_t                 log;
	u_int8_t                 logif;
	u_int8_t                 quick;
	u_int8_t                 ifnot;
	u_int8_t                 match_tag_not;
	u_int8_t                 natpass;

#define PF_STATE_NORMAL         0x1
#define PF_STATE_MODULATE       0x2
#define PF_STATE_SYNPROXY       0x3
	u_int8_t                 keep_state;
	sa_family_t              af;
	u_int8_t                 proto;
	u_int8_t                 type;
	u_int8_t                 code;
	u_int8_t                 flags;
	u_int8_t                 flagset;
	u_int8_t                 min_ttl;
	u_int8_t                 allow_opts;
	u_int8_t                 rt;
	u_int8_t                 return_ttl;

/* service class categories */
#define SCIDX_MASK              0x0f
#define SC_BE                   0x10
#define SC_BK_SYS               0x11
#define SC_BK                   0x12
#define SC_RD                   0x13
#define SC_OAM                  0x14
#define SC_AV                   0x15
#define SC_RV                   0x16
#define SC_VI                   0x17
#define SC_SIG                  0x17
#define SC_VO                   0x18
#define SC_CTL                  0x19

/* diffserve code points */
#define DSCP_MASK               0xfc
#define DSCP_CUMASK             0x03
#define DSCP_EF                 0xb8
#define DSCP_AF11               0x28
#define DSCP_AF12               0x30
#define DSCP_AF13               0x38
#define DSCP_AF21               0x48
#define DSCP_AF22               0x50
#define DSCP_AF23               0x58
#define DSCP_AF31               0x68
#define DSCP_AF32               0x70
#define DSCP_AF33               0x78
#define DSCP_AF41               0x88
#define DSCP_AF42               0x90
#define DSCP_AF43               0x98
#define AF_CLASSMASK            0xe0
#define AF_DROPPRECMASK         0x18
	u_int8_t                 tos;
	u_int8_t                 anchor_relative;
	u_int8_t                 anchor_wildcard;

#define PF_FLUSH                0x01
#define PF_FLUSH_GLOBAL         0x02
	u_int8_t                 flush;

	u_int8_t                proto_variant;
	u_int8_t                extfilter; /* Filter mode [PF_EXTFILTER_xxx] */
	u_int8_t                extmap;    /* Mapping mode [PF_EXTMAP_xxx] */
	u_int32_t               dnpipe;
	u_int32_t               dntype;
};

struct pfioc_pooladdr {
	u_int32_t                action;
	u_int32_t                ticket;
	u_int32_t                nr;
	u_int32_t                r_num;
	u_int8_t                 r_action;
	u_int8_t                 r_last;
	u_int8_t                 af;
	char                     anchor[MAXPATHLEN];
	struct pf_pooladdr       addr;
};

struct pfioc_rule {
	u_int32_t        action;
	u_int32_t        ticket;
	u_int32_t        pool_ticket;
	u_int32_t        nr;
	char             anchor[MAXPATHLEN];
	char             anchor_call[MAXPATHLEN];
	struct pf_rule   rule;
};

#define DIOCGETRULES _IOWR('D', 6, struct pfioc_rule)
#define DIOCGETRULE _IOWR('D', 7, struct pfioc_rule)
#define DIOCCHANGERULE _IOWR('D', 26, struct pfioc_rule)
#define DIOCBEGINADDRS _IOWR('D', 51, struct pfioc_pooladdr)
#endif
