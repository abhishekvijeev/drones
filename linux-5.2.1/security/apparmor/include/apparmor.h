/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AppArmor security module
 *
 * This file contains AppArmor basic global
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2017 Canonical Ltd.
 */

#ifndef __APPARMOR_H
#define __APPARMOR_H

#include <linux/types.h>


// Custom code: start
// Headers for ioctl() interface
#include <linux/module.h>	
#include <linux/kernel.h>	
#include <linux/init.h>		
#include <linux/ioctl.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/types.h>

typedef s64 tag_t;

struct flag_struct
{
    int flag;
};

#define TASKCTXIO 'r'

#define SET_FLAG _IO(TASKCTXIO, 0)
#define CLEAR_FLAG _IO(TASKCTXIO, 1)
#define SET_KERNEL_FLAG _IO(TASKCTXIO, 2)
#define CLEAR_KERNEL_FLAG _IO(TASKCTXIO, 3)
// Custom code: end




/*
 * Class of mediation types in the AppArmor policy db
 */
#define AA_CLASS_ENTRY		0
#define AA_CLASS_UNKNOWN	1
#define AA_CLASS_FILE		2
#define AA_CLASS_CAP		3
#define AA_CLASS_DEPRECATED	4
#define AA_CLASS_RLIMITS	5
#define AA_CLASS_DOMAIN		6
#define AA_CLASS_MOUNT		7
#define AA_CLASS_PTRACE		9
#define AA_CLASS_SIGNAL		10
#define AA_CLASS_NET		14
#define AA_CLASS_LABEL		16

#define AA_CLASS_LAST		AA_CLASS_LABEL

/* Control parameters settable through module/boot flags */
extern enum audit_mode aa_g_audit;
extern bool aa_g_audit_header;
extern bool aa_g_debug;
extern bool aa_g_hash_policy;
extern bool aa_g_lock_policy;
extern bool aa_g_logsyscall;
extern bool aa_g_paranoid_load;
extern unsigned int aa_g_path_max;

static int print_all_domain(struct aa_profile *profile);
static int apparmor_getlabel_domain (struct aa_profile *profile, char **name);
static int apparmor_check_for_flow (struct aa_profile *profile, char *checking_domain, bool *allow);
static int apparmor_domain_declassify (struct aa_profile *profile, u32 check_ip_addr, bool *allow);
static int apparmor_socket_label_compare(__u32 sender_pid, __u32 receiver_pid);


#endif /* __APPARMOR_H */
