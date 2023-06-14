// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Anton Protopopov
#ifndef __TCPCONNECT_H
#define __TCPCONNECT_H

#include "mntns_filter.h"

/* The maximum number of items in maps */
#define MAX_ENTRIES 8192

/* The maximum number of ports to filter */
#define MAX_PORTS 64

#define TASK_COMM_LEN 16

struct ipv4_flow_key {
	__u32 saddr;
	__u32 daddr;
	__u16 dport;
};

struct ipv6_flow_key {
	__u8 saddr[16];
	__u8 daddr[16];
	__u16 dport;
};

union ip_addr {
	__u8 v6[16];
	__u32 v4;
};

struct event {
	union ip_addr src;
	union ip_addr dst;

//	union {
//		__u8 saddr_v6[16];
//		__u32 saddr_v4;
//	};
//	union {
//		__u8 daddr_v6[16];
//		__u32 daddr_v4;
//	};
	__u8 task[TASK_COMM_LEN];
	__u64 timestamp;
	__u32 pid;
	__u32 uid;
	__u32 gid;
	__u16 version; // 4 or 6
	__u16 dport;
	__u16 sport;
	mnt_ns_id_t mntns_id;
	__u64 latency;
};

#endif /* __TCPCONNECT_H */
