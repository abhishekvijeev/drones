// SPDX-License-Identifier: GPL-2.0-only
/*
 * AppArmor security module
 *
 * This file contains AppArmor LSM hooks.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 */

#include <linux/lsm_hooks.h>
#include <linux/moduleparam.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/ptrace.h>
#include <linux/ctype.h>
#include <linux/sysctl.h>
#include <linux/audit.h>
#include <linux/user_namespace.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <net/sock.h>
#include <uapi/linux/mount.h>
#include <linux/string.h>
#include <linux/rwlock.h>
#include <uapi/linux/rtnetlink.h>
#include <linux/inetdevice.h>
#include <linux/skbuff.h>
#include <linux/pid.h>
#include <linux/msg.h>
#include <linux/xattr.h>

#include "include/apparmor.h"
#include "include/apparmorfs.h"
#include "include/audit.h"
#include "include/capability.h"
#include "include/cred.h"
#include "include/file.h"
#include "include/ipc.h"
#include "include/net.h"
#include "include/path.h"
#include "include/label.h"
#include "include/policy.h"
#include "include/policy_ns.h"
#include "include/procattr.h"
#include "include/mount.h"
#include "include/secid.h"



/* Flag indicating whether initialization completed */
int apparmor_initialized;
//defined in apparmor/include/lib.h as extern
int apparmor_ioctl_debug;

DEFINE_PER_CPU(struct aa_buffers, aa_buffers);



static int print_all_domain(struct aa_profile *profile)
{
	if (apparmor_ioctl_debug)
	{
		if (profile->current_domain)
		{
			printk (KERN_INFO "print_all_domain: current domain is %s set for process %s with pid %d\n", profile->current_domain->domain, current->comm, current->pid);
		}
		else
		{
			printk (KERN_INFO "print_all_domain: current domain is NOT set for process %s with pid %d\n", current->comm, current->pid);
		}
	}
	return 0;
	
}

static int apparmor_getlabel_domain (struct aa_profile *profile, char **name)
{
	if (profile->current_domain != NULL && profile->current_domain->domain != NULL)
	{
		*name = profile->current_domain->domain;
		
	}
	return 0;
}
static int apparmor_check_for_flow (struct aa_profile *profile, char *checking_domain, bool *allow)
{
	*allow = false;
	struct ListOfDomains *iterator;
	if (profile->allow_net_domains)
	{
		list_for_each_entry(iterator, &(profile->allow_net_domains->domain_list), domain_list)
		{
			// printk (KERN_INFO "apparmor_check_for_flow: Matching between %s, %s\n", iterator->domain, checking_domain);
			if ((strcmp(iterator->domain, checking_domain) == 0) || strcmp(iterator->domain, "*") == 0)
			{
				*allow = true;
				break;
			}
		}
	}
	return 0;
}

static int apparmor_domain_declassify (struct aa_profile *profile, u32 check_ip_addr, bool *allow)
{
	struct ListOfIPAddrs *iterator;
	if (profile->allowed_ip_addrs)
	{
		list_for_each_entry(iterator, &(profile->allowed_ip_addrs->ip_addr_list), ip_addr_list)
		{
			// printk (KERN_INFO "apparmor_domain_declassify: Matching between %u, %u\n", iterator->ip_addr, check_ip_addr);
			if (iterator->ip_addr == 0 || iterator->ip_addr == check_ip_addr)
			{
				*allow = true;
				break;
			}
		}
	}
	return 0;
}
#define MAX_LABEL_CACHE_SIZE 20
struct label_cache
{
	pid_t pid;
	struct aa_label *cur_label;

}label_cache_arr[MAX_LABEL_CACHE_SIZE];

static int apparmor_tsk_container_add(struct aa_label *label, pid_t pid)
{
	int ret = 0, i;
	static int remove_idx = 0;
	for(i = 0; i < MAX_LABEL_CACHE_SIZE; i++)
	{
		if(label_cache_arr[i].pid == pid)
		{
			ret = 1;
			break;
		}
		else if (label_cache_arr[i].pid == 0)
		{
			label_cache_arr[i].pid = pid;
			label_cache_arr[i].cur_label = aa_get_label(label);
			ret = 1;
			break;
		}
	}
	if (ret == 0)
	{
		// printk (KERN_INFO "apparmor_tsk_container_add: adding data at idx %d, pid %d, label %s\n", remove_idx, pid, label->hname);
		if (label_cache_arr[remove_idx].cur_label != NULL)
			aa_put_label(label_cache_arr[remove_idx].cur_label);

		label_cache_arr[remove_idx].pid = pid;
		label_cache_arr[remove_idx].cur_label = aa_get_label(label);
		remove_idx += 1;
		remove_idx %= MAX_LABEL_CACHE_SIZE;
	}
	else
	{
		// printk (KERN_INFO "apparmor_tsk_container_add: adding data at idx %d, pid %d, label %s\n", i, pid, label->hname);
		
	}
	


	return ret;	
}
static struct aa_label *apparmor_tsk_container_get(pid_t pid)
{
	struct aa_label *ret = NULL;
	int i;
	for(i = 0; i < MAX_LABEL_CACHE_SIZE; i++)
	{
		if (label_cache_arr[i].pid == pid && label_cache_arr[i].cur_label != NULL)
		{
			ret = label_cache_arr[i].cur_label;
			break;
		}
	}
	if (ret != NULL)
	{
		// printk (KERN_INFO "apparmor_tsk_container_get: data found at idx %d, pid %d, label %s\n", i, pid, ret->hname);
	}
	else
	{
		// printk (KERN_INFO "apparmor_tsk_container_get: data not found  of pid %d\n", pid);
	}
	return ret;
}
static int apparmor_tsk_container_remove(pid_t pid)
{
	int ret = 0, i;
	char *hname = " ";
	for(i = 0; i < MAX_LABEL_CACHE_SIZE; i++)
	{
		if(label_cache_arr[i].pid == pid)
		{
			if (label_cache_arr[i].cur_label != NULL)
				aa_put_label(label_cache_arr[i].cur_label);
			label_cache_arr[i].pid = 0;
			hname = label_cache_arr[i].cur_label->hname;
			label_cache_arr[i].cur_label = NULL;
			ret = 1;
		}
	}
	if (ret == 1)
	{
		// printk (KERN_INFO "apparmor_tsk_container_get: data removed at idx %d, pid %d, label %s\n", i, pid, hname);
	}
	
	return ret;	
}

static struct aa_label *apparmor_socket_label_compare_helper(__u32 pid)
{
	struct task_struct *task_data;
	struct aa_label *ret = NULL;
	task_data = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
	if (task_data == NULL)
	{
		ret = apparmor_tsk_container_get(pid);
	}
	else
	{
		ret = aa_get_task_label(task_data);
	}
	return ret;
}

static int apparmor_socket_label_compare(__u32 sender_pid, __u32 receiver_pid)
{
	struct aa_profile *profile;
	bool allow = false;		
	struct aa_label *sender_label, *receiver_label;
	char *receiver_domain = NULL;
	int err = 0;
	
	if (sender_pid != receiver_pid && sender_pid != 0 && receiver_pid != 0)
	{
		sender_label = apparmor_socket_label_compare_helper(sender_pid);
		if (sender_label != NULL)
		{
			sender_label = aa_get_label(sender_label);
		}
		receiver_label = apparmor_socket_label_compare_helper(receiver_pid);
		if (receiver_label != NULL)
		{
			receiver_label = aa_get_label(receiver_label);
		}
		if (sender_label != NULL && receiver_label != NULL)
		{
				
			fn_for_each (receiver_label, profile, apparmor_getlabel_domain(profile, &receiver_domain));
			if (receiver_domain != NULL)
			{
				fn_for_each (sender_label, profile, apparmor_check_for_flow(profile, receiver_domain, &allow));
				if (allow == 0)
					err = 1;
				else
					printk (KERN_INFO "[GRAPH_GEN] Process %s, socket_ipc, %s\n", sender_label->hname, receiver_label->hname);
				
			}
			
			// printk (KERN_INFO "apparmor_socket_label_compare: receiver process = %s, pid = %d, sent from process %s, pid = %d, Match is %d\n", receiver_label->hname, receiver_pid, sender_label->hname, sender_pid, allow);
		
		}
		if (sender_label != NULL)
			aa_put_label(sender_label);
		
		if (receiver_label != NULL)
			aa_put_label(receiver_label);
	}
	return err;
}


static int apparmor_inode_read_flow(struct inode *inode)
{
	struct aa_profile *profile;
	struct aa_label *curr_label, *sender_label;
	char *curr_domain = NULL;
	bool allow = false;
	int ret = 0;
	curr_label = __begin_current_label_crit_section();
	fn_for_each (curr_label, profile, apparmor_getlabel_domain(profile, &curr_domain));
	
	if(curr_domain)
	{
		void *addr = inode->i_security;
		if (addr != NULL)
		{
			sender_label = (struct aa_label *)inode->i_security;
			if (sender_label != NULL)
			{
				fn_for_each (sender_label, profile, apparmor_check_for_flow(profile, curr_domain, &allow));
				if (!allow)
					ret = 1;
				
			}
			// printk (KERN_INFO "apparmor_inode_read_flow: current process %s is reading from file %s, allowed %d\n", current->comm, sender_label->hname, allow);
		}
		
	}

	__end_current_label_crit_section(curr_label);
	if (ret)
		return -EPERM;
	return 0;
	
}

static int apparmor_inode_write_flow(struct inode *inode)
{
	struct aa_profile *profile;
	struct aa_label *curr_label, *inode_label;
	char *curr_domain = NULL;
	bool allow = false;
	int ret = 0;
	curr_label = __begin_current_label_crit_section();
	fn_for_each (curr_label, profile, apparmor_getlabel_domain(profile, &curr_domain));
	
	if(curr_domain)
	{
		void *addr = inode->i_security;
		if (addr != NULL)
		{
			inode_label = (struct aa_label *)inode->i_security;
			
			if (inode_label != NULL)
			{
				char *inode_domain = NULL;
				fn_for_each (inode_label, profile, apparmor_getlabel_domain(profile, &inode_domain));

				if (inode_domain != NULL)
				{
					fn_for_each (curr_label, profile, apparmor_check_for_flow(profile, inode_domain, &allow));
					if (!allow)
						ret = 1;
					
					//only if the owner is writing to the file, update the policy
					if (allow && strcmp(curr_domain, inode_domain) == 0)
					{
						//decrease the ref count for previous label,
						aa_put_label(inode_label);
						//update the inode label with new process
						inode->i_security = aa_get_label(curr_label);
						// printk (KERN_INFO "apparmor_inode_write_flow: label updated\n");
						
					}
				}
				
				
			}
			
			
			// printk (KERN_INFO "apparmor_inode_write_flow: current process %s is writing to file %s, allowed %d\n", current->comm, inode_label->hname, allow);
				
		}
		else
		{
			//update the label
			inode->i_security = aa_get_label(curr_label);
			// printk (KERN_INFO "apparmor_inode_write_flow: label added to previous existing file\n");
		}
		
		
		
	}

	__end_current_label_crit_section(curr_label);
	if (ret)
		return -EPERM;
	return 0;
	
}



/*
 * LSM hook functions
 */

/*
 * put the associated labels
 */
static void apparmor_cred_free(struct cred *cred)
{
	aa_put_label(cred_label(cred));
	set_cred_label(cred, NULL);
}

/*
 * allocate the apparmor part of blank credentials
 */
static int apparmor_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	set_cred_label(cred, NULL);
	return 0;
}

/*
 * prepare new cred label for modification by prepare_cred block
 */
static int apparmor_cred_prepare(struct cred *new, const struct cred *old,
				 gfp_t gfp)
{
	set_cred_label(new, aa_get_newest_label(cred_label(old)));
	return 0;
}

/*
 * transfer the apparmor data to a blank set of creds
 */
static void apparmor_cred_transfer(struct cred *new, const struct cred *old)
{
	set_cred_label(new, aa_get_newest_label(cred_label(old)));
}

static void apparmor_task_free(struct task_struct *task)
{
	// struct aa_profile *profile;
	// char *curr_domain = NULL;
	// struct aa_label *curr_label;
	
	// curr_label = aa_get_task_label(task);
	// fn_for_each (curr_label, profile, apparmor_getlabel_domain(profile, &curr_domain));
	// if (curr_domain != NULL)
	// {
	// 	int ret = apparmor_tsk_container_remove(task->pid);
	// 	printk (KERN_INFO "apparmor_task_free: remove label cache for task %s, pid %d, result is %d\n", task->comm, task->pid, ret);
		
	// }


	aa_free_task_ctx(task_ctx(task));
}

static int apparmor_task_alloc(struct task_struct *task,
			       unsigned long clone_flags)
{
	struct aa_task_ctx *new = task_ctx(task);

	aa_dup_task_ctx(new, task_ctx(current));

	return 0;
}

static int apparmor_ptrace_access_check(struct task_struct *child,
					unsigned int mode)
{
	struct aa_label *tracer, *tracee;
	int error;

	tracer = __begin_current_label_crit_section();
	tracee = aa_get_task_label(child);
	error = aa_may_ptrace(tracer, tracee,
			(mode & PTRACE_MODE_READ) ? AA_PTRACE_READ
						  : AA_PTRACE_TRACE);
	aa_put_label(tracee);
	__end_current_label_crit_section(tracer);

	return error;
}

static int apparmor_ptrace_traceme(struct task_struct *parent)
{
	struct aa_label *tracer, *tracee;
	int error;

	tracee = __begin_current_label_crit_section();
	tracer = aa_get_task_label(parent);
	error = aa_may_ptrace(tracer, tracee, AA_PTRACE_TRACE);
	aa_put_label(tracer);
	__end_current_label_crit_section(tracee);

	return error;
}

/* Derived from security/commoncap.c:cap_capget */
static int apparmor_capget(struct task_struct *target, kernel_cap_t *effective,
			   kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	struct aa_label *label;
	const struct cred *cred;

	rcu_read_lock();
	cred = __task_cred(target);
	label = aa_get_newest_cred_label(cred);

	/*
	 * cap_capget is stacked ahead of this and will
	 * initialize effective and permitted.
	 */
	if (!unconfined(label)) {
		struct aa_profile *profile;
		struct label_it i;

		label_for_each_confined(i, label, profile) {
			if (COMPLAIN_MODE(profile))
				continue;
			*effective = cap_intersect(*effective,
						   profile->caps.allow);
			*permitted = cap_intersect(*permitted,
						   profile->caps.allow);
		}
	}
	rcu_read_unlock();
	aa_put_label(label);

	return 0;
}

static int apparmor_capable(const struct cred *cred, struct user_namespace *ns,
			    int cap, unsigned int opts)
{
	struct aa_label *label;
	int error = 0;

	label = aa_get_newest_cred_label(cred);
	if (!unconfined(label))
		error = aa_capable(label, cap, opts);
	aa_put_label(label);

	return error;
}

/**
 * common_perm - basic common permission check wrapper fn for paths
 * @op: operation being checked
 * @path: path to check permission of  (NOT NULL)
 * @mask: requested permissions mask
 * @cond: conditional info for the permission request  (NOT NULL)
 *
 * Returns: %0 else error code if error or permission denied
 */
static int common_perm(const char *op, const struct path *path, u32 mask,
		       struct path_cond *cond)
{
	struct aa_label *label;
	int error = 0;

	label = __begin_current_label_crit_section();
	if (!unconfined(label))
		error = aa_path_perm(op, label, path, 0, mask, cond);
	__end_current_label_crit_section(label);

	return error;
}

/**
 * common_perm_cond - common permission wrapper around inode cond
 * @op: operation being checked
 * @path: location to check (NOT NULL)
 * @mask: requested permissions mask
 *
 * Returns: %0 else error code if error or permission denied
 */
static int common_perm_cond(const char *op, const struct path *path, u32 mask)
{
	struct path_cond cond = { d_backing_inode(path->dentry)->i_uid,
				  d_backing_inode(path->dentry)->i_mode
	};

	if (!path_mediated_fs(path->dentry))
		return 0;

	return common_perm(op, path, mask, &cond);
}

/**
 * common_perm_dir_dentry - common permission wrapper when path is dir, dentry
 * @op: operation being checked
 * @dir: directory of the dentry  (NOT NULL)
 * @dentry: dentry to check  (NOT NULL)
 * @mask: requested permissions mask
 * @cond: conditional info for the permission request  (NOT NULL)
 *
 * Returns: %0 else error code if error or permission denied
 */
static int common_perm_dir_dentry(const char *op, const struct path *dir,
				  struct dentry *dentry, u32 mask,
				  struct path_cond *cond)
{
	struct path path = { .mnt = dir->mnt, .dentry = dentry };

	return common_perm(op, &path, mask, cond);
}

/**
 * common_perm_rm - common permission wrapper for operations doing rm
 * @op: operation being checked
 * @dir: directory that the dentry is in  (NOT NULL)
 * @dentry: dentry being rm'd  (NOT NULL)
 * @mask: requested permission mask
 *
 * Returns: %0 else error code if error or permission denied
 */
static int common_perm_rm(const char *op, const struct path *dir,
			  struct dentry *dentry, u32 mask)
{
	struct inode *inode = d_backing_inode(dentry);
	struct path_cond cond = { };

	if (!inode || !path_mediated_fs(dentry))
		return 0;

	cond.uid = inode->i_uid;
	cond.mode = inode->i_mode;

	return common_perm_dir_dentry(op, dir, dentry, mask, &cond);
}

/**
 * common_perm_create - common permission wrapper for operations doing create
 * @op: operation being checked
 * @dir: directory that dentry will be created in  (NOT NULL)
 * @dentry: dentry to create   (NOT NULL)
 * @mask: request permission mask
 * @mode: created file mode
 *
 * Returns: %0 else error code if error or permission denied
 */
static int common_perm_create(const char *op, const struct path *dir,
			      struct dentry *dentry, u32 mask, umode_t mode)
{
	struct path_cond cond = { current_fsuid(), mode };

	if (!path_mediated_fs(dir->dentry))
		return 0;

	return common_perm_dir_dentry(op, dir, dentry, mask, &cond);
}

static int apparmor_path_unlink(const struct path *dir, struct dentry *dentry)
{
	return common_perm_rm(OP_UNLINK, dir, dentry, AA_MAY_DELETE);
}

static int apparmor_path_mkdir(const struct path *dir, struct dentry *dentry,
			       umode_t mode)
{
	return common_perm_create(OP_MKDIR, dir, dentry, AA_MAY_CREATE,
				  S_IFDIR);
}

static int apparmor_path_rmdir(const struct path *dir, struct dentry *dentry)
{
	return common_perm_rm(OP_RMDIR, dir, dentry, AA_MAY_DELETE);
}

static int apparmor_path_mknod(const struct path *dir, struct dentry *dentry,
			       umode_t mode, unsigned int dev)
{
	return common_perm_create(OP_MKNOD, dir, dentry, AA_MAY_CREATE, mode);
}

static int apparmor_path_truncate(const struct path *path)
{
	return common_perm_cond(OP_TRUNC, path, MAY_WRITE | AA_MAY_SETATTR);
}

static int apparmor_path_symlink(const struct path *dir, struct dentry *dentry,
				 const char *old_name)
{
	return common_perm_create(OP_SYMLINK, dir, dentry, AA_MAY_CREATE,
				  S_IFLNK);
}

static int apparmor_path_link(struct dentry *old_dentry, const struct path *new_dir,
			      struct dentry *new_dentry)
{
	struct aa_label *label;
	int error = 0;

	if (!path_mediated_fs(old_dentry))
		return 0;

	label = begin_current_label_crit_section();
	if (!unconfined(label))
		error = aa_path_link(label, old_dentry, new_dir, new_dentry);
	end_current_label_crit_section(label);

	return error;
}

static int apparmor_path_rename(const struct path *old_dir, struct dentry *old_dentry,
				const struct path *new_dir, struct dentry *new_dentry)
{
	struct aa_label *label;
	int error = 0;

	if (!path_mediated_fs(old_dentry))
		return 0;

	label = begin_current_label_crit_section();
	if (!unconfined(label)) {
		struct path old_path = { .mnt = old_dir->mnt,
					 .dentry = old_dentry };
		struct path new_path = { .mnt = new_dir->mnt,
					 .dentry = new_dentry };
		struct path_cond cond = { d_backing_inode(old_dentry)->i_uid,
					  d_backing_inode(old_dentry)->i_mode
		};

		error = aa_path_perm(OP_RENAME_SRC, label, &old_path, 0,
				     MAY_READ | AA_MAY_GETATTR | MAY_WRITE |
				     AA_MAY_SETATTR | AA_MAY_DELETE,
				     &cond);
		if (!error)
			error = aa_path_perm(OP_RENAME_DEST, label, &new_path,
					     0, MAY_WRITE | AA_MAY_SETATTR |
					     AA_MAY_CREATE, &cond);

	}
	end_current_label_crit_section(label);

	return error;
}

static int apparmor_path_chmod(const struct path *path, umode_t mode)
{
	return common_perm_cond(OP_CHMOD, path, AA_MAY_CHMOD);
}

static int apparmor_path_chown(const struct path *path, kuid_t uid, kgid_t gid)
{
	return common_perm_cond(OP_CHOWN, path, AA_MAY_CHOWN);
}

static int apparmor_inode_getattr(const struct path *path)
{
	return common_perm_cond(OP_GETATTR, path, AA_MAY_GETATTR);
}

static int apparmor_inode_alloc_security(struct inode *inode)
{
	// struct aa_profile *profile;
	// struct aa_label *curr_label;
	// char *curr_domain = NULL;
	// curr_label = __begin_current_label_crit_section();
	// fn_for_each (curr_label, profile, apparmor_getlabel_domain(profile, &curr_domain));
	// if(curr_domain)
	// {
	// 	printk(KERN_INFO "apparmor_inode_alloc_security (%s)\n", current->comm);
	// 	inode->i_security = aa_get_label(curr_label);
	// }

	// __end_current_label_crit_section(curr_label);

	return 0;
}

static void apparmor_inode_free_security(struct inode *inode)
{
	// if(inode->i_security)
	// {
	// 	struct aa_label *inode_label = (struct aa_label *)inode->i_security;
	// 	aa_put_label(inode_label);
	// }
}




static int apparmor_file_open(struct file *file)
{
	struct aa_file_ctx *fctx = file_ctx(file);
	struct aa_label *label;
	int error = 0;

	if (!path_mediated_fs(file->f_path.dentry))
		return 0;

	/* If in exec, permission is handled by bprm hooks.
	 * Cache permissions granted by the previous exec check, with
	 * implicit read and executable mmap which are required to
	 * actually execute the image.
	 */
	if (current->in_execve) {
		fctx->allow = MAY_EXEC | MAY_READ | AA_EXEC_MMAP;
		return 0;
	}

	label = aa_get_newest_cred_label(file->f_cred);
	if (!unconfined(label)) {
		struct inode *inode = file_inode(file);
		struct path_cond cond = { inode->i_uid, inode->i_mode };

		error = aa_path_perm(OP_OPEN, label, &file->f_path, 0,
				     aa_map_file_to_perms(file), &cond);
		/* todo cache full allowed permissions set and state */
		fctx->allow = aa_map_file_to_perms(file);
	}
	aa_put_label(label);

	return error;
}

static int apparmor_file_alloc_security(struct file *file)
{
	struct aa_file_ctx *ctx = file_ctx(file);
	struct aa_label *label = begin_current_label_crit_section();

	spin_lock_init(&ctx->lock);
	rcu_assign_pointer(ctx->label, aa_get_label(label));
	end_current_label_crit_section(label);
	return 0;
}

static void apparmor_file_free_security(struct file *file)
{
	struct aa_file_ctx *ctx = file_ctx(file);

	if (ctx)
		aa_put_label(rcu_access_pointer(ctx->label));
}

static int common_file_perm(const char *op, struct file *file, u32 mask)
{
	struct aa_label *label;
	int error = 0;

	/* don't reaudit files closed during inheritance */
	if (file->f_path.dentry == aa_null.dentry)
		return -EACCES;

	label = __begin_current_label_crit_section();
	error = aa_file_perm(op, label, file, mask);

	__end_current_label_crit_section(label);

	return error;
}

static int apparmor_file_receive(struct file *file)
{
	return common_file_perm(OP_FRECEIVE, file, aa_map_file_to_perms(file));
}


bool apparmor_check_domain_in_xattrs(char *domain, char *xattr_buf)
{
	bool present = false;

	char *found;

    while( (found = strsep(&xattr_buf,",")) != NULL )
	{
		if(strcmp(domain, found) == 0)
		{
			present = true;
			break;
		}
	}
        
	return present;
}

static int apparmor_calc_context_len(struct aa_profile *profile, int *context_len)
{
	struct ListOfDomains *iterator;
	if (profile->allow_net_domains)
	{
		list_for_each_entry(iterator, &(profile->allow_net_domains->domain_list), domain_list)
		{
			*context_len += strlen(iterator->domain) + 1;
		}
	}
	return 0;
}

static int apparmor_create_context(struct aa_profile *profile, char **context)
{
	struct ListOfDomains *iterator;
	if (profile->allow_net_domains)
	{
		list_for_each_entry(iterator, &(profile->allow_net_domains->domain_list), domain_list)
		{
			*context = strcat(*context, iterator->domain);
			*context = strcat(*context, ",");
		}
	}
	return 0;
}

static void apparmor_setxattr(struct file *file, char *curr_domain)
{
	struct dentry *dentry = file->f_path.dentry;
	struct aa_label *curr_label;
	struct aa_profile *profile;
	char *context = NULL;
	int context_len = 0;

	context_len += strlen(curr_domain) + 1;

	curr_label = __begin_current_label_crit_section();
	fn_for_each (curr_label, profile, apparmor_calc_context_len(profile, &context_len));
	
	
	context = kzalloc(context_len + 1, GFP_KERNEL);
	context = strcat(context, curr_domain);
	context = strcat(context, ",");
	fn_for_each (curr_label, profile, apparmor_create_context(profile, &context));

	__end_current_label_crit_section(curr_label);

	context[context_len] = '\0';

	// printk(KERN_INFO "apparmor_file_permission (%s): setting xattrs of file %s to %s\n", current->comm, file->f_path.dentry->d_iname, context);


	__vfs_setxattr_noperm(dentry, XATTR_NAME_APPARMOR, context, context_len, 0);
}

static char *apparmor_get_domain_from_xattrs(char *context)
{
	char *found;
	found = strsep(&context,",");
	return found;
}



static int apparmor_file_permission(struct file *file, int mask)
{
	
	#define INITCONTEXTLEN 255

	struct aa_profile *profile;
	struct aa_label *curr_label;
	char *curr_domain = NULL;
	struct dentry *dentry = file->f_path.dentry;
	struct inode *inode = file->f_path.dentry->d_inode;
	char *context;
	int len = 0;
	int rc = 0;
	uid_t uid = inode->i_uid.val;
	uid_t euid = current->cred->euid.val;
	


	int aa_perm = 0;

	// First perform AppArmor MAC checks
	// Only if MAC policy allows operation on the file do we perform xattr operations

	aa_perm = common_file_perm(OP_FPERM, file, mask);


		
	if(uid == 0 || euid == 0 )
	{
		return 0;
	}

	

	if(aa_perm == 0 && dentry != NULL)
	{
		//perform our additional xattr work if MAC checks succeed
		curr_label = aa_get_task_label(current);
		if (curr_label != NULL)
		{
			fn_for_each (curr_label, profile, apparmor_getlabel_domain(profile, &curr_domain));
			
			if(curr_domain)
			{
				if (dentry != NULL)
				{
					char *tmppath = kzalloc(300, GFP_KERNEL);
					if (tmppath != NULL)
					{
						char *fullpath = dentry_path_raw(dentry, tmppath, 300);
						if (mask == AA_MAY_EXEC)
							printk (KERN_INFO "[GRAPH_GEN] Process %s, exec_file, %s\n", curr_label->hname, fullpath);
						else if (mask ==  AA_MAY_WRITE)
							printk (KERN_INFO "[GRAPH_GEN] Process %s, write_file, %s\n", curr_label->hname, fullpath);
						else if (mask ==  AA_MAY_READ)
							printk (KERN_INFO "[GRAPH_GEN] Process %s, read_file, %s\n", curr_label->hname, fullpath);
						else if (mask ==  AA_MAY_APPEND)
							printk (KERN_INFO "[GRAPH_GEN] Process %s, append_file, %s\n", curr_label->hname, fullpath);
						else if (mask ==  AA_MAY_CREATE)
							printk (KERN_INFO "[GRAPH_GEN] Process %s, create_file, %s\n", curr_label->hname, fullpath);
						else if (mask ==  AA_MAY_DELETE)
							printk (KERN_INFO "[GRAPH_GEN] Process %s, delete_file, %s\n", curr_label->hname, fullpath);
						else if (mask ==  AA_MAY_RENAME)
							printk (KERN_INFO "[GRAPH_GEN] Process %s, rename_file, %s\n", curr_label->hname, fullpath);
						
						kzfree(tmppath);
					}
					
				}
				// Code to retrieve xattr borrowed from SELinux hooks.c - function inode_doinit_use_xattr()

				len = INITCONTEXTLEN;
				context = kmalloc(len + 1, GFP_NOFS);
				rc = __vfs_getxattr(dentry, inode, XATTR_NAME_APPARMOR, context, len);

				if(mask == AA_MAY_READ)
				{
					if(rc > 0)
					{
						// Process with domain trying to read from a file with xattrs set - perform the check
						if(apparmor_check_domain_in_xattrs(curr_domain, context))
						{
							// printk(KERN_INFO "apparmor_file_permission (%s): process with domain %s ALLOW read from file %s\n", current->comm, curr_domain, file->f_path.dentry->d_iname);
							return 0;
						}
						else
						{
							// printk(KERN_INFO "apparmor_file_permission (%s): process with domain %s DENY read from file %s\n", current->comm, curr_domain, file->f_path.dentry->d_iname);
							return -EPERM;
						}
						
					}
					else
					{
						if (rc == -ENODATA || rc == -EOPNOTSUPP || rc == 0) 
						{
							// The file has no xattrs set - ALLOW READ
							// printk(KERN_INFO "apparmor_file_permission (%s): process with domain %s ALLOW read from file %s - no xattrs set\n", current->comm, curr_domain, file->f_path.dentry->d_iname);
							return 0;
						}
						else
						{
							// Error while trying to get xattrs from file - return error code
							// printk(KERN_INFO "apparmor_file_permission (%s): Error -%d while trying to get xattrs from file %s \n", current->comm, rc, file->f_path.dentry->d_iname);
							return rc;
						}
					}
					
				}//end of if(mask == AA_MAY_READ)

				else if(mask == AA_MAY_WRITE)
				{
					if(rc > 0)
					{
						// The file has extended attributes stored

						// Process with domain trying to write to an already labeled file
						// Here, we must check whether the writing process is the same one that wrote to it first
						// If so, check whether the file's label is stale and in this case update it. Finally ALLOW the operation
						// If not, deny the operation because every file will only contain the data of the process that 
						// first writes to it
						char *file_domain = apparmor_get_domain_from_xattrs(context);
						if(strcmp(file_domain, curr_domain) == 0)
						{
							// Process is the same one that wrote to it first - update the file's label and allow write
							//??Maybe we need to track all files so that we can remove it when label changes??
							inode_lock(inode);
							apparmor_setxattr(file, curr_domain);
							inode_unlock(inode);
							// printk(KERN_INFO "apparmor_file_permission (%s): writing to file %s with NEW XATTRS UPDATED. \n", current->comm, file->f_path.dentry->d_iname);
							return 0;
						}
						else
						{
							// Process is the different from the one that wrote to it first - DENY
							// printk(KERN_INFO "apparmor_file_permission (%s): DENIED UPDATED! setting xattrs of file %s to %s\n", current->comm, file->f_path.dentry->d_iname, context);
							return -EPERM;
						}
						
						
					}
					else
					{
						if (rc == -ENODATA || rc == -EOPNOTSUPP || rc == 0) 
						{
							// The file has no extended attributes stored
							// Process with a domain trying to write for the first time to a file without xattrs.
							// We set the xattrs of a file to contain the allow_list of the first process that writes to it
							// printk(KERN_INFO "apparmor_file_permission (%s): process with domain %s trying to write for the first time to file %s without xattrs\n", current->comm, curr_domain, file->f_path.dentry->d_iname, context);
							inode_lock(inode);
							apparmor_setxattr(file, curr_domain);
							inode_unlock(inode);
						}
						else
						{
							// Error while trying to get xattrs from file - return error code
							// printk(KERN_INFO "apparmor_file_permission (%s): Error -%d while trying to get xattrs from file %s \n", current->comm, rc, file->f_path.dentry->d_iname);
							return rc;
						}
					}
					
				}//end of else if(mask == AA_MAY_WRITE)
			}

			aa_put_label(curr_label);
		}//end of curr_label != NUL
		

		

		
	}

	

	return aa_perm;

}

static int apparmor_file_lock(struct file *file, unsigned int cmd)
{
	u32 mask = AA_MAY_LOCK;

	if (cmd == F_WRLCK)
		mask |= MAY_WRITE;

	return common_file_perm(OP_FLOCK, file, mask);
}

static int common_mmap(const char *op, struct file *file, unsigned long prot,
		       unsigned long flags)
{
	int mask = 0;

	if (!file || !file_ctx(file))
		return 0;

	if (prot & PROT_READ)
		mask |= MAY_READ;
	/*
	 * Private mappings don't require write perms since they don't
	 * write back to the files
	 */
	if ((prot & PROT_WRITE) && !(flags & MAP_PRIVATE))
		mask |= MAY_WRITE;
	if (prot & PROT_EXEC)
		mask |= AA_EXEC_MMAP;

	return common_file_perm(op, file, mask);
}

static int apparmor_mmap_file(struct file *file, unsigned long reqprot,
			      unsigned long prot, unsigned long flags)
{
	return common_mmap(OP_FMMAP, file, prot, flags);
}

static int apparmor_file_mprotect(struct vm_area_struct *vma,
				  unsigned long reqprot, unsigned long prot)
{
	return common_mmap(OP_FMPROT, vma->vm_file, prot,
			   !(vma->vm_flags & VM_SHARED) ? MAP_PRIVATE : 0);
}

static int apparmor_sb_mount(const char *dev_name, const struct path *path,
			     const char *type, unsigned long flags, void *data)
{
	struct aa_label *label;
	int error = 0;

	/* Discard magic */
	if ((flags & MS_MGC_MSK) == MS_MGC_VAL)
		flags &= ~MS_MGC_MSK;

	flags &= ~AA_MS_IGNORE_MASK;

	label = __begin_current_label_crit_section();
	if (!unconfined(label)) {
		if (flags & MS_REMOUNT)
			error = aa_remount(label, path, flags, data);
		else if (flags & MS_BIND)
			error = aa_bind_mount(label, path, dev_name, flags);
		else if (flags & (MS_SHARED | MS_PRIVATE | MS_SLAVE |
				  MS_UNBINDABLE))
			error = aa_mount_change_type(label, path, flags);
		else if (flags & MS_MOVE)
			error = aa_move_mount(label, path, dev_name);
		else
			error = aa_new_mount(label, dev_name, path, type,
					     flags, data);
	}
	__end_current_label_crit_section(label);

	return error;
}

static int apparmor_sb_umount(struct vfsmount *mnt, int flags)
{
	struct aa_label *label;
	int error = 0;

	label = __begin_current_label_crit_section();
	if (!unconfined(label))
		error = aa_umount(label, mnt, flags);
	__end_current_label_crit_section(label);

	return error;
}

static int apparmor_sb_pivotroot(const struct path *old_path,
				 const struct path *new_path)
{
	struct aa_label *label;
	int error = 0;

	label = aa_get_current_label();
	if (!unconfined(label))
		error = aa_pivotroot(label, old_path, new_path);
	aa_put_label(label);

	return error;
}

static int apparmor_getprocattr(struct task_struct *task, char *name,
				char **value)
{
	int error = -ENOENT;
	/* released below */
	const struct cred *cred = get_task_cred(task);
	struct aa_task_ctx *ctx = task_ctx(current);
	struct aa_label *label = NULL;

	if (strcmp(name, "current") == 0)
		label = aa_get_newest_label(cred_label(cred));
	else if (strcmp(name, "prev") == 0  && ctx->previous)
		label = aa_get_newest_label(ctx->previous);
	else if (strcmp(name, "exec") == 0 && ctx->onexec)
		label = aa_get_newest_label(ctx->onexec);
	else
		error = -EINVAL;

	if (label)
		error = aa_getprocattr(label, value);

	aa_put_label(label);
	put_cred(cred);

	return error;
}

static int apparmor_setprocattr(const char *name, void *value,
				size_t size)
{
	char *command, *largs = NULL, *args = value;
	size_t arg_size;
	int error;
	DEFINE_AUDIT_DATA(sa, LSM_AUDIT_DATA_NONE, OP_SETPROCATTR);

	if (size == 0)
		return -EINVAL;

	/* AppArmor requires that the buffer must be null terminated atm */
	if (args[size - 1] != '\0') {
		/* null terminate */
		largs = args = kmalloc(size + 1, GFP_KERNEL);
		if (!args)
			return -ENOMEM;
		memcpy(args, value, size);
		args[size] = '\0';
	}

	error = -EINVAL;
	args = strim(args);
	command = strsep(&args, " ");
	if (!args)
		goto out;
	args = skip_spaces(args);
	if (!*args)
		goto out;

	arg_size = size - (args - (largs ? largs : (char *) value));
	if (strcmp(name, "current") == 0) {
		if (strcmp(command, "changehat") == 0) {
			error = aa_setprocattr_changehat(args, arg_size,
							 AA_CHANGE_NOFLAGS);
		} else if (strcmp(command, "permhat") == 0) {
			error = aa_setprocattr_changehat(args, arg_size,
							 AA_CHANGE_TEST);
		} else if (strcmp(command, "changeprofile") == 0) {
			error = aa_change_profile(args, AA_CHANGE_NOFLAGS);
		} else if (strcmp(command, "permprofile") == 0) {
			error = aa_change_profile(args, AA_CHANGE_TEST);
		} else if (strcmp(command, "stack") == 0) {
			error = aa_change_profile(args, AA_CHANGE_STACK);
		} else
			goto fail;
	} else if (strcmp(name, "exec") == 0) {
		if (strcmp(command, "exec") == 0)
			error = aa_change_profile(args, AA_CHANGE_ONEXEC);
		else if (strcmp(command, "stack") == 0)
			error = aa_change_profile(args, (AA_CHANGE_ONEXEC |
							 AA_CHANGE_STACK));
		else
			goto fail;
	} else
		/* only support the "current" and "exec" process attributes */
		goto fail;

	if (!error)
		error = size;
out:
	kfree(largs);
	return error;

fail:
	aad(&sa)->label = begin_current_label_crit_section();
	aad(&sa)->info = name;
	aad(&sa)->error = error = -EINVAL;
	aa_audit_msg(AUDIT_APPARMOR_DENIED, &sa, NULL);
	end_current_label_crit_section(aad(&sa)->label);
	goto out;
}

/**
 * apparmor_bprm_committing_creds - do task cleanup on committing new creds
 * @bprm: binprm for the exec  (NOT NULL)
 */
static void apparmor_bprm_committing_creds(struct linux_binprm *bprm)
{
	struct aa_label *label = aa_current_raw_label();
	struct aa_label *new_label = cred_label(bprm->cred);

	/* bail out if unconfined or not changing profile */
	if ((new_label->proxy == label->proxy) ||
	    (unconfined(new_label)))
		return;

	aa_inherit_files(bprm->cred, current->files);

	current->pdeath_signal = 0;

	/* reset soft limits and set hard limits for the new label */
	__aa_transition_rlimits(label, new_label);
}

/**
 * apparmor_bprm_committed_cred - do cleanup after new creds committed
 * @bprm: binprm for the exec  (NOT NULL)
 */
static void apparmor_bprm_committed_creds(struct linux_binprm *bprm)
{
	/* clear out temporary/transitional state from the context */
	aa_clear_task_ctx_trans(task_ctx(current));

	return;
}

static void apparmor_task_getsecid(struct task_struct *p, u32 *secid)
{
	struct aa_label *label = aa_get_task_label(p);
	*secid = label->secid;
	aa_put_label(label);
}

static int apparmor_task_setrlimit(struct task_struct *task,
		unsigned int resource, struct rlimit *new_rlim)
{
	struct aa_label *label = __begin_current_label_crit_section();
	int error = 0;

	if (!unconfined(label))
		error = aa_task_setrlimit(label, task, resource, new_rlim);
	__end_current_label_crit_section(label);

	return error;
}

static int apparmor_task_kill(struct task_struct *target, struct kernel_siginfo *info,
			      int sig, const struct cred *cred)
{
	struct aa_label *cl, *tl;
	int error;

	if (cred) {
		/*
		 * Dealing with USB IO specific behavior
		 */
		cl = aa_get_newest_cred_label(cred);
		tl = aa_get_task_label(target);
		error = aa_may_signal(cl, tl, sig);
		aa_put_label(cl);
		aa_put_label(tl);
		return error;
	}

	cl = __begin_current_label_crit_section();
	tl = aa_get_task_label(target);
	error = aa_may_signal(cl, tl, sig);
	aa_put_label(tl);
	__end_current_label_crit_section(cl);

	return error;
}

/**
 * apparmor_sk_alloc_security - allocate and attach the sk_security field
 */
static int apparmor_sk_alloc_security(struct sock *sk, int family, gfp_t flags)
{
	struct aa_sk_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), flags);
	if (!ctx)
		return -ENOMEM;

	SK_CTX(sk) = ctx;

	return 0;
}

/**
 * apparmor_sk_free_security - free the sk_security field
 */
static void apparmor_sk_free_security(struct sock *sk)
{
	struct aa_sk_ctx *ctx = SK_CTX(sk);

	SK_CTX(sk) = NULL;
	aa_put_label(ctx->label);
	aa_put_label(ctx->peer);
	kfree(ctx);
}

/**
 * apparmor_clone_security - clone the sk_security field
 */
static void apparmor_sk_clone_security(const struct sock *sk,
				       struct sock *newsk)
{
	struct aa_sk_ctx *ctx = SK_CTX(sk);
	struct aa_sk_ctx *new = SK_CTX(newsk);

	new->label = aa_get_label(ctx->label);
	new->peer = aa_get_label(ctx->peer);
}


static int apparmor_unix_may_send (struct socket *sock, struct socket *other)
{
	struct aa_sk_ctx *ctx_sender = SK_CTX(sock->sk);
	struct aa_label *sender_label = aa_get_label(ctx_sender->label);

	struct aa_sk_ctx *ctx_recv = SK_CTX(other->sk);
	struct aa_label *recv_label = aa_get_label(ctx_recv->label);
	printk (KERN_INFO "apparmor_unix_may_send: Current process %s\n", current->comm);
		
	if (sender_label != NULL && recv_label != NULL)
	{
		printk (KERN_INFO "apparmor_unix_may_send: sender = %s, receiver = %s\n", sender_label->hname, recv_label->hname);
		
		aa_put_label(sender_label);
		aa_put_label(recv_label);
		
	}
	return 0;
	
}

/**
 * apparmor_socket_create - check perms before creating a new socket
 */
static int apparmor_socket_create(int family, int type, int protocol, int kern)
{
	struct aa_label *label;
	int error = 0;

	AA_BUG(in_interrupt());

	label = begin_current_label_crit_section();
	if (!(kern || unconfined(label)))
		error = af_select(family,
				  create_perm(label, family, type, protocol),
				  aa_af_perm(label, OP_CREATE, AA_MAY_CREATE,
					     family, type, protocol));
	end_current_label_crit_section(label);

	return error;
}

/**
 * apparmor_socket_post_create - setup the per-socket security struct
 *
 * Note:
 * -   kernel sockets currently labeled unconfined but we may want to
 *     move to a special kernel label
 * -   socket may not have sk here if created with sock_create_lite or
 *     sock_alloc. These should be accept cases which will be handled in
 *     sock_graft.
 */
static int apparmor_socket_post_create(struct socket *sock, int family,
				       int type, int protocol, int kern)
{
	struct aa_label *label;

	if (kern) {
		struct aa_ns *ns = aa_get_current_ns();

		label = aa_get_label(ns_unconfined(ns));
		aa_put_ns(ns);
	} else
		label = aa_get_current_label();

	if (sock->sk) {
		struct aa_sk_ctx *ctx = SK_CTX(sock->sk);

		aa_put_label(ctx->label);
		ctx->label = aa_get_label(label);
	}
	aa_put_label(label);

	return 0;
}

/**
 * apparmor_socket_bind - check perms before bind addr to socket
 */
static int apparmor_socket_bind(struct socket *sock,
				struct sockaddr *address, int addrlen)
{
	AA_BUG(!sock);
	AA_BUG(!sock->sk);
	AA_BUG(!address);
	AA_BUG(in_interrupt());

	return af_select(sock->sk->sk_family,
			 bind_perm(sock, address, addrlen),
			 aa_sk_perm(OP_BIND, AA_MAY_BIND, sock->sk));
}

/**
 * apparmor_socket_connect - check perms before connecting @sock to @address
 */
static int apparmor_socket_connect(struct socket *sock,
				   struct sockaddr *address, int addrlen)
{
	AA_BUG(!sock);
	AA_BUG(!sock->sk);
	AA_BUG(!address);
	AA_BUG(in_interrupt());


	return af_select(sock->sk->sk_family,
			 connect_perm(sock, address, addrlen),
			 aa_sk_perm(OP_CONNECT, AA_MAY_CONNECT, sock->sk));
}

/**
 * apparmor_socket_list - check perms before allowing listen
 */
static int apparmor_socket_listen(struct socket *sock, int backlog)
{
	AA_BUG(!sock);
	AA_BUG(!sock->sk);
	AA_BUG(in_interrupt());

	return af_select(sock->sk->sk_family,
			 listen_perm(sock, backlog),
			 aa_sk_perm(OP_LISTEN, AA_MAY_LISTEN, sock->sk));
}

/**
 * apparmor_socket_accept - check perms before accepting a new connection.
 *
 * Note: while @newsock is created and has some information, the accept
 *       has not been done.
 */
static int apparmor_socket_accept(struct socket *sock, struct socket *newsock)
{
	AA_BUG(!sock);
	AA_BUG(!sock->sk);
	AA_BUG(!newsock);
	AA_BUG(in_interrupt());

	return af_select(sock->sk->sk_family,
			 accept_perm(sock, newsock),
			 aa_sk_perm(OP_ACCEPT, AA_MAY_ACCEPT, sock->sk));
}

static int aa_sock_msg_perm(const char *op, u32 request, struct socket *sock,
			    struct msghdr *msg, int size)
{
	AA_BUG(!sock);
	AA_BUG(!sock->sk);
	AA_BUG(!msg);
	AA_BUG(in_interrupt());

	return af_select(sock->sk->sk_family,
			 msg_perm(op, request, sock, msg, size),
			 aa_sk_perm(op, request, sock->sk));
}

static int apparmor_extract_daddr(struct msghdr *msg, struct sock *sk)
{
	struct inet_sock *inet;
	inet = inet_sk(sk);
				
	u32 daddr = 0;
	DECLARE_SOCKADDR(struct sockaddr_in *, usin, msg->msg_name);
	if (usin) 
	{
		if (msg->msg_namelen < sizeof(*usin))
			return -EINVAL;
		if (usin->sin_family != AF_INET) 
		{
			if (usin->sin_family != AF_UNSPEC)
				return -EAFNOSUPPORT;
		}

		daddr = usin->sin_addr.s_addr;
	} 
	else 
	{
		if (sk->sk_state != TCP_ESTABLISHED)
			return -EDESTADDRREQ;
		daddr = inet->inet_daddr;
	}
	return daddr;
}


/**
 * apparmor_socket_sendmsg - check perms before sending msg to another socket
 */
static int apparmor_socket_sendmsg(struct socket *sock,
				   struct msghdr *msg, int size)
{
	struct sock *sk = sock->sk;
    struct aa_label *curr_label, *curr_sock_label;
	bool allow = false;
	struct aa_label *cl;
	struct aa_profile *profile;
    u32 daddr = 0;
	struct aa_sk_ctx *ctx = SK_CTX(sk);
	char *curr_domain = NULL;
	int error = 1;


	cl = __begin_current_label_crit_section();	
	curr_label = aa_get_task_label(current);
	if(!unconfined(cl) && ctx != NULL && ctx->label != NULL && curr_label != NULL)
	{
		curr_sock_label = aa_get_label(ctx->label);
		
		//reset the recv_pid
		if (curr_sock_label->pid != current->pid)
		{
			curr_sock_label->recv_pid = 0;
		}
		curr_sock_label->pid = current->pid;

		//get the domain from current process label and not from socket's label, coz socket's can be passed
		fn_for_each (curr_label, profile, apparmor_getlabel_domain(profile, &curr_domain));
		
		if (curr_domain != NULL)
		{
			int ret = apparmor_tsk_container_add(curr_label, current->pid);
			// printk (KERN_INFO "apparmor_socket_sendmsg (%s): current_pid = %d, sk_family=%d, sock->type=%d\n", current->comm, current->pid, sock->sk->sk_family, sock->type);
			if(sk->sk_family == AF_INET)
			{   
				int ret_val = 0;
			
				int tmp = apparmor_extract_daddr(msg, sk);
				if (tmp > 0)
					daddr = tmp;
				else
				{
					// printk (KERN_INFO "apparmor_socket_sendmsg: unable to get destination address\n");
					goto sendmsg_out;
				}
				
				// 1. Check if packet destination is localhost
				if(localhost_address(daddr))
				{
					ret_val = 1;
					// printk(KERN_INFO "apparmor_socket_sendmsg (%s): Packet from localhost to localhost allowed, current_pid = %d\n", current->comm, current->pid);
				}
				

				// 2. Check if packet destination is DDS multicast address
				else if(ntohs(daddr) == 61439)
				{
					ret_val = 1;
					// printk(KERN_INFO "apparmor_socket_sendmsg (%s): DDS Multicast allowed %pi4, current_pid = %d\n", current->comm, &daddr, current->pid);
				}

				// 3. Check if destination address is multicast address
				else if(((daddr & 0x000000FF) >= 224) && ((daddr & 0x000000FF) <= 239))
				{
					ret_val = 1;
					// printk(KERN_INFO "apparmor_socket_sendmsg (%s): Multicast address allowed %pi4, current_pid = %d\n", current->comm, &daddr, current->pid);
				}
				
				/* 
				* 4. Otherwise, the packet's destination is outside the machine
				* Perform domain declassification by obtaining the list of allowed domains
				* for the sending process
				*/
				else
				{
					// printk(KERN_INFO "apparmor_socket_sendmsg: Message from process %s to outside address %pi4, addr = %u, ntohs(addr) = %u, daddr & 0xFF000000 = %u, ntohs(daddr) & 0xFF000000 = %u, addr & 0x000000FF = %u, ntohs(daddr) & 0x000000FF = %u\n", current->comm, &daddr, daddr, ntohs(daddr), daddr & 0xFF000000, ntohs(daddr) & 0xFF000000, daddr & 0x000000FF, ntohs(daddr) & 0x000000FF);					

					fn_for_each (curr_label, profile, apparmor_domain_declassify(profile, daddr, &allow));
					if(allow)
					{
						ret_val = 1;
						printk (KERN_INFO "[GRAPH_GEN] Process %s, network, %pi4\n", curr_label->hname, &daddr);
					}
					// printk(KERN_INFO "apparmor_socket_sendmsg (%s): Domain declassification for message from process %s(pid = %d) to address %pi4, flow is %d\n", current->comm, current->comm, current->pid, &daddr, allow);
				}
				if (ret_val == 0)
					error = 0;
				
				
			}//end of if(sk->sk_family == AF_INET)
			else if(sk->sk_family == AF_UNIX)
			{
				printk (KERN_INFO "apparmor_socket_sendmsg: UNIX DOMAIN SOCKET \n");
				printk (KERN_INFO "apparmor_socket_sendmsg: address pair = %lld, port_pair = %d \n", sock->sk->sk_addrpair, sock->sk->sk_portpair);
				printk (KERN_INFO "apparmor_socket_sendmsg: desti addr = %d, desti port = %d,  sk_rcv_saddr = %d, sk_num = %d \n", sock->sk->sk_daddr, 														sock->sk->sk_dport, sock->sk->sk_rcv_saddr, sock->sk->sk_num);
				
			}
		
		}//end if (curr_domain != NULL)
		sendmsg_out:
		aa_put_label(curr_sock_label);
		
	}
	
	aa_put_label(curr_label);
	__end_current_label_crit_section(cl);
	if (error == 0)
	{
		// printk (KERN_INFO "apparmor_socket_sendmsg (%s): return is -13\n", current->comm);
		return -EACCES;
	}
	else
		return aa_sock_msg_perm(OP_SENDMSG, AA_MAY_SEND, sock, msg, size);
}


/**
 * apparmor_socket_recvmsg - check perms before receiving a message
 */
static int apparmor_socket_recvmsg(struct socket *sock,
				   struct msghdr *msg, int size, int flags)
{
	struct aa_label *curr_label, *curr_sock_label, *cl;
	struct aa_profile *profile;
	struct task_struct *sender;
	bool allow = false;		
	__u32 sender_pid;
	struct aa_sk_ctx *ctx = SK_CTX(sock->sk);
	struct aa_label *sender_label;
	char *curr_domain = NULL;
	int error = 1;

	cl = __begin_current_label_crit_section();
	curr_label = aa_get_task_label(current);
	if(!unconfined(cl) && ctx != NULL && ctx->label != NULL && curr_label != NULL)
	{
		curr_sock_label = aa_get_label(ctx->label);

		//get the domain from current process label and not from socket's label, coz socket's can be passed
		fn_for_each (curr_label, profile, apparmor_getlabel_domain(profile, &curr_domain));
		curr_sock_label->recv_pid = current->pid;

		if (curr_domain != NULL && curr_sock_label->pid != 0)
		{
			// printk (KERN_INFO "apparmor_socket_recvmsg (%s): current_pid %d, sk_family=%d, sock->type=%d\n", current->comm, current->pid, sock->sk->sk_family, sock->type);
			
			if(sock->sk->sk_family == AF_INET)
			{
				sender_pid = curr_sock_label->pid;
				// sender = pid_task(find_vpid(sender_pid), PIDTYPE_PID);
				sender = get_pid_task(find_get_pid(sender_pid), PIDTYPE_PID);
				if (sender == NULL)
				{
					sender_label = apparmor_tsk_container_get(sender_pid);
					if (sender_label != NULL)
					{
						sender_label = aa_get_label(sender_label);
					}
				}
				else
				{
					sender_label = aa_get_task_label(sender);
				}

				if (sender_label != NULL)
				{
					if (sender_pid != current->pid )
					{
						//add sender & receiver label to cache
						int ret = apparmor_tsk_container_add(curr_label, current->pid);

						fn_for_each (sender_label, profile, apparmor_check_for_flow(profile, curr_domain, &allow));
						if (allow == 0)
							error = 0;
						else
							printk (KERN_INFO "[GRAPH_GEN] Process %s, socket_ipc, %s\n", sender_label->hname, curr_label->hname);
						
						// printk (KERN_INFO "apparmor_socket_recvmsg (%s): Match is %d for flow from %s(pid = %d) to %s(pid = %d)\n", current->comm, allow, sender_label->hname, sender_pid, current->comm, current->pid);
					}
					
					aa_put_label(sender_label);	
				}
				else
				{
					// printk (KERN_INFO "apparmor_socket_recvmsg (%s): else statement for (if (sender_pid != current->pid && sender_label != NULL)) sender pid: %d, current pid: %d\n", current->comm, sender_pid, current->pid);
				}
				
				
				
				
			}//end of if(sock->sk->sk_family == AF_INET )
			else if(sock->sk->sk_family == AF_UNIX)
			{
				printk (KERN_INFO "apparmor_socket_recvmsg: UNIX DOMAIN SOCKET \n");
				printk (KERN_INFO "apparmor_socket_recvmsg: address pair = %lld, port_pair = %d \n", sock->sk->sk_addrpair, sock->sk->sk_portpair);
				printk (KERN_INFO "apparmor_socket_recvmsg: desti addr = %d, desti port = %d,  sk_rcv_saddr = %d, sk_num = %d \n", sock->sk->sk_daddr, 														sock->sk->sk_dport, sock->sk->sk_rcv_saddr, sock->sk->sk_num);
				
			}
		} // end for if (curr_domain != NULL)	
		aa_put_label(curr_sock_label);
	}
	

	aa_put_label(curr_label);
	__end_current_label_crit_section(cl);
	if (error == 0)
	{
		bool drop_flag = false;
		if (sock && sock->sk)
		{
			struct sk_buff_head *list = &sock->sk->sk_receive_queue;
			struct sk_buff *skb;
			while ((skb = __skb_dequeue(list)) != NULL)
			{
				//instead use sk_eat_skb() from sock.h
				kfree_skb(skb);
				drop_flag = true;
			}
		}
		// printk (KERN_INFO "apparmor_socket_recvmsg (%s): return is -13, status of drop_flag = %d\n", current->comm, drop_flag);
		return -EACCES;
	}
	else
		return aa_sock_msg_perm(OP_RECVMSG, AA_MAY_RECEIVE, sock, msg, size);
}

/* revaliation, get/set attr, shutdown */
static int aa_sock_perm(const char *op, u32 request, struct socket *sock)
{
	AA_BUG(!sock);
	AA_BUG(!sock->sk);
	AA_BUG(in_interrupt());

	return af_select(sock->sk->sk_family,
			 sock_perm(op, request, sock),
			 aa_sk_perm(op, request, sock->sk));
}

/**
 * apparmor_socket_getsockname - check perms before getting the local address
 */
static int apparmor_socket_getsockname(struct socket *sock)
{
	return aa_sock_perm(OP_GETSOCKNAME, AA_MAY_GETATTR, sock);
}

/**
 * apparmor_socket_getpeername - check perms before getting remote address
 */
static int apparmor_socket_getpeername(struct socket *sock)
{
	return aa_sock_perm(OP_GETPEERNAME, AA_MAY_GETATTR, sock);
}

/* revaliation, get/set attr, opt */
static int aa_sock_opt_perm(const char *op, u32 request, struct socket *sock,
			    int level, int optname)
{
	AA_BUG(!sock);
	AA_BUG(!sock->sk);
	AA_BUG(in_interrupt());

	return af_select(sock->sk->sk_family,
			 opt_perm(op, request, sock, level, optname),
			 aa_sk_perm(op, request, sock->sk));
}

/**
 * apparmor_getsockopt - check perms before getting socket options
 */
static int apparmor_socket_getsockopt(struct socket *sock, int level,
				      int optname)
{
	return aa_sock_opt_perm(OP_GETSOCKOPT, AA_MAY_GETOPT, sock,
				level, optname);
}

/**
 * apparmor_setsockopt - check perms before setting socket options
 */
static int apparmor_socket_setsockopt(struct socket *sock, int level,
				      int optname)
{
	return aa_sock_opt_perm(OP_SETSOCKOPT, AA_MAY_SETOPT, sock,
				level, optname);
}

/**
 * apparmor_socket_shutdown - check perms before shutting down @sock conn
 */
static int apparmor_socket_shutdown(struct socket *sock, int how)
{
	return aa_sock_perm(OP_SHUTDOWN, AA_MAY_SHUTDOWN, sock);
}

#ifdef CONFIG_NETWORK_SECMARK

int localhost_address(u32 ip_addr)
{
	struct net_device *dev;
	u32 dev_addr;
	if((ip_addr & 0x000000FF) == 127)
	{
		// printk(KERN_INFO "localhost_address: Packet from localhost: %pi4\n", &ip_addr);
		return 1;
	}

	read_lock(&dev_base_lock);
	dev = first_net_device(&init_net);
	while (dev) 
	{
		dev_addr = inet_select_addr(dev, 0, RT_SCOPE_UNIVERSE);
		if(dev_addr == ip_addr)
		{
			// printk(KERN_INFO "localhost_address: IP address %pi4 equals device IP addr %pi4\n", &ip_addr, &dev_addr);
			read_unlock(&dev_base_lock);
			return 1;
		}
		dev = next_net_device(dev);
	}
	read_unlock(&dev_base_lock);

	return 0;
	
}

/**
 * apparmor_socket_sock_recv_skb - check perms before associating skb to sk
 *
 * Note: can not sleep may be called with locks held
 *
 * dont want protocol specific in __skb_recv_datagram()
 * to deny an incoming connection  socket_sock_rcv_skb()
 */
static int apparmor_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	struct aa_sk_ctx *ctx = SK_CTX(sk);
	struct aa_label *label;
	struct aa_profile *profile;
    char *curr_domain = NULL;
	
	int error = 0;
	if (ctx != NULL && ctx->label != NULL)
	{
		label = aa_get_label(ctx->label);
		const struct tcphdr *tcpheader;
		
		fn_for_each (label, profile, apparmor_getlabel_domain(profile, &curr_domain));

		if(curr_domain != NULL && (sk->sk_type == SOCK_STREAM))
		{
			tcpheader = tcp_hdr(skb);
			if (skb->secmark != label->pid && skb->secmark != 0)
				label->pid = skb->secmark;
			// printk (KERN_INFO "apparmor_socket_sock_rcv_skb: TCP socket label_name: %s, label->pid %d, label->recv_pid %d, skb->pid %d, skb->data_len %d, syn = %d, ack = %d, fin = %d\n", label->hname, label->pid, label->recv_pid, skb->secmark, skb->data_len, tcpheader->syn, tcpheader->ack, tcpheader->fin);
			int ret = apparmor_socket_label_compare(label->pid, label->recv_pid);
			if (ret != 0)
			{
				error = 1;
			}
		}

		// if (curr_domain != NULL && (sk->sk_type == SOCK_DGRAM || 
			// (sk->sk_type == SOCK_STREAM && tcpheader->fin != 1 && tcpheader->syn != 1 && tcpheader->ack != 1  )))

		else if (curr_domain != NULL && (sk->sk_type == SOCK_DGRAM))
		{
			// printk (KERN_INFO "apparmor_socket_sock_rcv_skb: UDP socket label_name: %s, label->pid %d, label->recv_pid %d, skb->pid %d, skb->data_len %d\n", label->hname, label->pid, label->recv_pid, skb->secmark, skb->data_len);
			// printk (KERN_INFO "skb len %d skb data_len %d\n", skb->len, skb->data_len);
			int ret = apparmor_socket_label_compare(label->pid, label->recv_pid);
			if (ret != 0)
			{
				error = 1;
			}
		}
		
		aa_put_label(ctx->label);		
	}
	

	if (error)
	{
		// printk (KERN_INFO "apparmor_socket_sock_rcv_skb: dropping packet at label_name: %s\n", label->hname);
		
		// if(sk->sk_type == SOCK_STREAM )
		// {
		// 	struct sk_buff *tmp = skb;
		// 	while (tmp != NULL)
		// 	{
		// 		printk (KERN_INFO "apparmor_socket_sock_rcv_skb skb data_len %d\n", tmp->data_len);
		// 		tmp = tmp->next;
		// 	}
		// 	//make data 0, but prob here is we dont know length of 
		// 	//data received
		// 	// void *tmp = skb_put(skb, skb->data_len);
		// 	// memset(tmp, 0, skb->data_len);
		// 	// printk (KERN_INFO "apparmor_socket_sock_rcv_skb: packet set to 0\n");
		
		// 	return 0;
		// }
		// else		
		return -EACCES;
	}
	
	if (!skb->secmark)
	{
		return 0;
	}

	return apparmor_secmark_check(ctx->label, OP_RECVMSG, AA_MAY_RECEIVE,
				      skb->secmark, sk);
}
#endif


static struct aa_label *sk_peer_label(struct sock *sk)
{
	struct aa_sk_ctx *ctx = SK_CTX(sk);

	if (ctx->peer)
		return ctx->peer;

	return ERR_PTR(-ENOPROTOOPT);
}

/**
 * apparmor_socket_getpeersec_stream - get security context of peer
 *
 * Note: for tcp only valid if using ipsec or cipso on lan
 */
static int apparmor_socket_getpeersec_stream(struct socket *sock,
					     char __user *optval,
					     int __user *optlen,
					     unsigned int len)
{
	char *name;
	int slen, error = 0;
	struct aa_label *label;
	struct aa_label *peer;

	label = begin_current_label_crit_section();
	peer = sk_peer_label(sock->sk);
	if (IS_ERR(peer)) {
		error = PTR_ERR(peer);
		goto done;
	}
	slen = aa_label_asxprint(&name, labels_ns(label), peer,
				 FLAG_SHOW_MODE | FLAG_VIEW_SUBNS |
				 FLAG_HIDDEN_UNCONFINED, GFP_KERNEL);
	/* don't include terminating \0 in slen, it breaks some apps */
	if (slen < 0) {
		error = -ENOMEM;
	} else {
		if (slen > len) {
			error = -ERANGE;
		} else if (copy_to_user(optval, name, slen)) {
			error = -EFAULT;
			goto out;
		}
		if (put_user(slen, optlen))
			error = -EFAULT;
out:
		kfree(name);

	}

done:
	end_current_label_crit_section(label);

	return error;
}

/**
 * apparmor_socket_getpeersec_dgram - get security label of packet
 * @sock: the peer socket
 * @skb: packet data
 * @secid: pointer to where to put the secid of the packet
 *
 * Sets the netlabel socket state on sk from parent
 */
static int apparmor_socket_getpeersec_dgram(struct socket *sock,
					    struct sk_buff *skb, u32 *secid)

{
	/* TODO: requires secid support */
	return -ENOPROTOOPT;
}

/**
 * apparmor_sock_graft - Initialize newly created socket
 * @sk: child sock
 * @parent: parent socket
 *
 * Note: could set off of SOCK_CTX(parent) but need to track inode and we can
 *       just set sk security information off of current creating process label
 *       Labeling of sk for accept case - probably should be sock based
 *       instead of task, because of the case where an implicitly labeled
 *       socket is shared by different tasks.
 */
static void apparmor_sock_graft(struct sock *sk, struct socket *parent)
{
	struct aa_sk_ctx *ctx = SK_CTX(sk);

	if (!ctx->label)
		ctx->label = aa_get_current_label();
}

#ifdef CONFIG_NETWORK_SECMARK
static int apparmor_inet_conn_request(struct sock *sk, struct sk_buff *skb,
				      struct request_sock *req)
{
	struct aa_sk_ctx *ctx = SK_CTX(sk);

	if (!skb->secmark)
		return 0;

	return apparmor_secmark_check(ctx->label, OP_CONNECT, AA_MAY_CONNECT,
				      skb->secmark, sk);
}
#endif


static void apparmor_shm_free_security(struct kern_ipc_perm *perm)
{
	// struct aa_profile *profile;
	// struct aa_label *curr_label;
	// char *curr_domain = NULL;
	// curr_label = aa_get_current_label();
	// fn_for_each (curr_label, profile, apparmor_getlabel_domain(profile, &curr_domain));
	// if (curr_domain != NULL)
	// {
	// 	printk(KERN_INFO "apparmor_shm_free_security (%s): key: %d\n", current->comm, perm->key);
	// 	aa_put_label((struct aa_label *) perm->security);	
	// }
	// aa_put_label(curr_label);
	void *tmpsecurity = perm->security;
	if (tmpsecurity)
	{
		struct ListOfDomains *perm_security_list = (struct ListOfDomains *)tmpsecurity;

		if(perm_security_list)
		{
			struct ListOfDomains *iterator, *tmp;
			iterator = list_first_entry(&(perm_security_list->domain_list), typeof(*iterator), domain_list);
			while((&iterator->domain_list) != &(perm_security_list->domain_list))
			{
				tmp = iterator;
				iterator = list_next_entry (iterator, domain_list);
				kzfree (tmp->domain);
				kzfree (tmp);
			}	
			// printk(KERN_INFO "apparmor_shm_free_security \n");
			//kfree(perm_security_list);
		}
	}
	
	
	
	
}
static int apparmor_shm_alloc_security(struct kern_ipc_perm *perm)
{
	struct aa_profile *profile;
	struct aa_label *curr_label;
	char *curr_domain = NULL;
	curr_label = __begin_current_label_crit_section();
	fn_for_each (curr_label, profile, apparmor_getlabel_domain(profile, &curr_domain));
	__end_current_label_crit_section(curr_label);

	if(curr_domain)
	{
		// printk(KERN_INFO "apparmor_shm_alloc_security (%s)\n", current->comm);

		struct ListOfDomains *perm_security_list = kzalloc(sizeof(struct ListOfDomains), GFP_KERNEL);
		if(perm_security_list)
		{
			INIT_LIST_HEAD(&(perm_security_list->domain_list));
			perm->security = perm_security_list;
		}
		
	}

	
	
	
	return 0;
}

static int apparmor_ipc_permission(struct kern_ipc_perm *ipcp, short flag)
{
	// printk(KERN_INFO "apparmor_ipc_permission (%s): key: %d, flag: %d\n", current->comm, ipcp->key, flag);
	return 0;
}


static int apparmor_shm_add_domain(char *curr_domain, struct ListOfDomains *perm_security_list)
{
	int curr_domain_len = strlen(curr_domain);
	struct ListOfDomains *new_node = kzalloc(sizeof(struct ListOfDomains), GFP_KERNEL);
	
	if (!new_node)
		return -ENOMEM;

	new_node->domain = kzalloc(curr_domain_len, GFP_KERNEL);
	if(!new_node->domain)
		return -ENOMEM;

	strncpy(new_node->domain, curr_domain, curr_domain_len);
	INIT_LIST_HEAD(&(new_node->domain_list));
	list_add(&(new_node->domain_list), &(perm_security_list->domain_list));
	return 0;
}

static int apparmor_check_domain_present(char *cur_domain, struct ListOfDomains *perm_security_list)
{
	struct ListOfDomains *iterator;
	list_for_each_entry(iterator, &(perm_security_list->domain_list), domain_list)
	{
		if (strcmp(iterator->domain, cur_domain) == 0)
		{
			return 1;
		}
	}
	return 0;
}
void apparmor_shm_graph_log(char *cur_domain, struct ListOfDomains *perm_security_list)
{
	struct ListOfDomains *iterator;
	list_for_each_entry(iterator, &(perm_security_list->domain_list), domain_list)
	{
		printk (KERN_INFO "[GRAPH_GEN] Process %s, shm_ipc, %s\n", cur_domain, iterator->domain);
		printk (KERN_INFO "[GRAPH_GEN] Process %s, shm_ipc, %s\n", iterator->domain, cur_domain);
		
	}
}


void apparmor_print_list_domain(struct ListOfDomains *perm_security_list)
{
	// printk(KERN_INFO "apparmor_shm_shmat (%s): shm security list:\n", current->comm);
	struct ListOfDomains *iterator;
	// list_for_each_entry(iterator, &(perm_security_list->domain_list), domain_list)
	// {
	// 	printk_ratelimited(KERN_INFO "%s\n", iterator->domain);
	// }
}


static int apparmor_shm_shmat(struct kern_ipc_perm *perm, char __user *shmaddr, int shmflg)
{
	
	struct aa_profile *profile;
	struct aa_label *curr_label;
	char *curr_domain = NULL;
	bool allow = false;
	curr_label = __begin_current_label_crit_section();
	fn_for_each (curr_label, profile, apparmor_getlabel_domain(profile, &curr_domain));
	__end_current_label_crit_section(curr_label);
	struct ListOfDomains *perm_security_list = (struct ListOfDomains *)perm->security;

	if(curr_domain != NULL && perm_security_list != NULL)
	{
		struct ListOfDomains *iterator;
		iterator = list_first_entry(&(perm_security_list->domain_list), typeof(*iterator), domain_list);
		while((&iterator->domain_list) != &(perm_security_list->domain_list))
		{
			fn_for_each (curr_label, profile, apparmor_check_for_flow(profile, iterator->domain, &allow));
			if(!allow)
			{
				return -EPERM;
			}
			iterator = list_next_entry (iterator, domain_list);
		}
		//TODO: check if all domains present in shared memory can write to current process

		if (apparmor_check_domain_present(curr_domain, perm_security_list) == 0)
		{
			if (apparmor_shm_add_domain(curr_domain, perm_security_list) < 0)
				return -EPERM;
		}
		apparmor_shm_graph_log(curr_domain, perm_security_list);
		apparmor_print_list_domain(perm_security_list);
	}
	
	

	return 0;
}

static int apparmor_msg_msg_alloc_security(struct msg_msg *msg)
{
	// printk(KERN_INFO "msg_msg_alloc_security: current = %s\n", current->comm);
	// printk(KERN_INFO "apparmor_msg_msg_alloc_security: current = %s\n", current->comm);
	struct aa_profile *profile;
	struct aa_label *curr_label;
	char *curr_domain = NULL;
	char *msg_label = NULL;
	curr_label = aa_get_task_label(current);
	if (curr_label != NULL)
	{
		fn_for_each (curr_label, profile, apparmor_getlabel_domain(profile, &curr_domain));
		if(curr_domain != NULL)
		{
			msg->pid = current->pid;
			apparmor_tsk_container_add(curr_label, current->pid);
			// printk(KERN_INFO "apparmor_msg_msg_alloc_security: attached label to message from process %s\n", current->comm);
		}
		aa_put_label(curr_label);
	}
	
	
	return 0;
}

static void apparmor_msg_msg_free_security(struct msg_msg *msg)
{	
	// if(msg->security)
	// {
	// 	printk(KERN_INFO "msg_msg_free_security: current = %s, ", current->comm);
	// }
}

static int apparmor_msg_queue_msgsnd(struct kern_ipc_perm *perm, struct msg_msg *msg,
				int msqflg)
{
	
	return 0;
}

static int apparmor_msg_queue_msgrcv(struct kern_ipc_perm *perm, struct msg_msg *msg,
				struct task_struct *target, long type,
				int mode)
{	
	int err = 0;

	struct aa_profile *profile;
	struct aa_label *curr_label, *sender_label;
	char *curr_domain = NULL;
	char *msg_label = NULL;
	curr_label = aa_get_task_label(current);
	if (curr_label != NULL)
	{
		fn_for_each (curr_label, profile, apparmor_getlabel_domain(profile, &curr_domain));
		if(curr_domain != NULL)
		{
			int pid = msg->pid;
			// printk (KERN_INFO "msg_queue_msgrcv: pid value %d\n", pid);
			sender_label = apparmor_tsk_container_get(pid);
			bool allow = false;
			if (sender_label != NULL)
			{
				fn_for_each (sender_label, profile, apparmor_check_for_flow(profile, curr_domain, &allow));
				if (allow == 0)
				{
					err = 1;
					// printk(KERN_INFO "msg_queue_msgrcv: err = 1 for flow from sender label %s to target\n", sender_label->hname, curr_label->hname);
				}
				else
					printk (KERN_INFO "[GRAPH_GEN] Process %s, msg_ipc, %s\n", sender_label->hname, curr_label->hname);
				aa_put_label(sender_label);
			}
			
			
			
		}
		aa_put_label(curr_label);
	}
	
	if (err != 0)
		return -EPERM;
	else
		return 0;
}

/*
 * The cred blob is a pointer to, not an instance of, an aa_task_ctx.
 */
struct lsm_blob_sizes apparmor_blob_sizes __lsm_ro_after_init = {
	.lbs_cred = sizeof(struct aa_task_ctx *),
	.lbs_file = sizeof(struct aa_file_ctx),
	.lbs_task = sizeof(struct aa_task_ctx),
	// .lbs_msg_msg = sizeof(struct msg_security_struct),
};

static struct security_hook_list apparmor_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(ptrace_access_check, apparmor_ptrace_access_check),
	LSM_HOOK_INIT(ptrace_traceme, apparmor_ptrace_traceme),
	LSM_HOOK_INIT(capget, apparmor_capget),
	LSM_HOOK_INIT(capable, apparmor_capable),

	LSM_HOOK_INIT(sb_mount, apparmor_sb_mount),
	LSM_HOOK_INIT(sb_umount, apparmor_sb_umount),
	LSM_HOOK_INIT(sb_pivotroot, apparmor_sb_pivotroot),

	LSM_HOOK_INIT(path_link, apparmor_path_link),
	LSM_HOOK_INIT(path_unlink, apparmor_path_unlink),
	LSM_HOOK_INIT(path_symlink, apparmor_path_symlink),
	LSM_HOOK_INIT(path_mkdir, apparmor_path_mkdir),
	LSM_HOOK_INIT(path_rmdir, apparmor_path_rmdir),
	LSM_HOOK_INIT(path_mknod, apparmor_path_mknod),
	LSM_HOOK_INIT(path_rename, apparmor_path_rename),
	LSM_HOOK_INIT(path_chmod, apparmor_path_chmod),
	LSM_HOOK_INIT(path_chown, apparmor_path_chown),
	LSM_HOOK_INIT(path_truncate, apparmor_path_truncate),
	LSM_HOOK_INIT(inode_getattr, apparmor_inode_getattr),

	LSM_HOOK_INIT(inode_alloc_security, apparmor_inode_alloc_security),
	LSM_HOOK_INIT(inode_free_security, apparmor_inode_free_security),

	



	LSM_HOOK_INIT(file_open, apparmor_file_open),
	LSM_HOOK_INIT(file_receive, apparmor_file_receive),
	LSM_HOOK_INIT(file_permission, apparmor_file_permission),
	LSM_HOOK_INIT(file_alloc_security, apparmor_file_alloc_security),
	LSM_HOOK_INIT(file_free_security, apparmor_file_free_security),
	LSM_HOOK_INIT(mmap_file, apparmor_mmap_file),
	LSM_HOOK_INIT(file_mprotect, apparmor_file_mprotect),
	LSM_HOOK_INIT(file_lock, apparmor_file_lock),





	LSM_HOOK_INIT(getprocattr, apparmor_getprocattr),
	LSM_HOOK_INIT(setprocattr, apparmor_setprocattr),

	LSM_HOOK_INIT(sk_alloc_security, apparmor_sk_alloc_security),
	LSM_HOOK_INIT(sk_free_security, apparmor_sk_free_security),
	LSM_HOOK_INIT(sk_clone_security, apparmor_sk_clone_security),


	LSM_HOOK_INIT(unix_may_send, apparmor_unix_may_send),
	LSM_HOOK_INIT(socket_create, apparmor_socket_create),
	LSM_HOOK_INIT(socket_post_create, apparmor_socket_post_create),
	LSM_HOOK_INIT(socket_bind, apparmor_socket_bind),
	LSM_HOOK_INIT(socket_connect, apparmor_socket_connect),
	LSM_HOOK_INIT(socket_listen, apparmor_socket_listen),
	LSM_HOOK_INIT(socket_accept, apparmor_socket_accept),
	LSM_HOOK_INIT(socket_sendmsg, apparmor_socket_sendmsg),
	LSM_HOOK_INIT(socket_recvmsg, apparmor_socket_recvmsg),
	LSM_HOOK_INIT(socket_getsockname, apparmor_socket_getsockname),
	LSM_HOOK_INIT(socket_getpeername, apparmor_socket_getpeername),
	LSM_HOOK_INIT(socket_getsockopt, apparmor_socket_getsockopt),
	LSM_HOOK_INIT(socket_setsockopt, apparmor_socket_setsockopt),
	LSM_HOOK_INIT(socket_shutdown, apparmor_socket_shutdown),
#ifdef CONFIG_NETWORK_SECMARK
	LSM_HOOK_INIT(socket_sock_rcv_skb, apparmor_socket_sock_rcv_skb),
#endif
	LSM_HOOK_INIT(socket_getpeersec_stream,
		      apparmor_socket_getpeersec_stream),
	LSM_HOOK_INIT(socket_getpeersec_dgram,
		      apparmor_socket_getpeersec_dgram),
	LSM_HOOK_INIT(sock_graft, apparmor_sock_graft),
#ifdef CONFIG_NETWORK_SECMARK
	LSM_HOOK_INIT(inet_conn_request, apparmor_inet_conn_request),
#endif

	LSM_HOOK_INIT(cred_alloc_blank, apparmor_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free, apparmor_cred_free),
	LSM_HOOK_INIT(cred_prepare, apparmor_cred_prepare),
	LSM_HOOK_INIT(cred_transfer, apparmor_cred_transfer),

	LSM_HOOK_INIT(bprm_set_creds, apparmor_bprm_set_creds),
	LSM_HOOK_INIT(bprm_committing_creds, apparmor_bprm_committing_creds),
	LSM_HOOK_INIT(bprm_committed_creds, apparmor_bprm_committed_creds),

	LSM_HOOK_INIT(task_free, apparmor_task_free),
	LSM_HOOK_INIT(task_alloc, apparmor_task_alloc),
	LSM_HOOK_INIT(task_getsecid, apparmor_task_getsecid),
	LSM_HOOK_INIT(task_setrlimit, apparmor_task_setrlimit),
	LSM_HOOK_INIT(task_kill, apparmor_task_kill),

#ifdef CONFIG_AUDIT
	LSM_HOOK_INIT(audit_rule_init, aa_audit_rule_init),
	LSM_HOOK_INIT(audit_rule_known, aa_audit_rule_known),
	LSM_HOOK_INIT(audit_rule_match, aa_audit_rule_match),
	LSM_HOOK_INIT(audit_rule_free, aa_audit_rule_free),
#endif

	LSM_HOOK_INIT(secid_to_secctx, apparmor_secid_to_secctx),
	LSM_HOOK_INIT(secctx_to_secid, apparmor_secctx_to_secid),
	LSM_HOOK_INIT(release_secctx, apparmor_release_secctx),

	LSM_HOOK_INIT(shm_alloc_security, apparmor_shm_alloc_security),
	LSM_HOOK_INIT(ipc_permission, apparmor_ipc_permission),
	LSM_HOOK_INIT(shm_shmat, apparmor_shm_shmat),
	LSM_HOOK_INIT(shm_free_security, apparmor_shm_free_security),

	LSM_HOOK_INIT(msg_msg_alloc_security, apparmor_msg_msg_alloc_security),
	LSM_HOOK_INIT(msg_msg_free_security, apparmor_msg_msg_free_security),
	LSM_HOOK_INIT(msg_queue_msgsnd, apparmor_msg_queue_msgsnd),
	LSM_HOOK_INIT(msg_queue_msgrcv, apparmor_msg_queue_msgrcv),
	
};

/*
 * AppArmor sysfs module parameters
 */

static int param_set_aabool(const char *val, const struct kernel_param *kp);
static int param_get_aabool(char *buffer, const struct kernel_param *kp);
#define param_check_aabool param_check_bool
static const struct kernel_param_ops param_ops_aabool = {
	.flags = KERNEL_PARAM_OPS_FL_NOARG,
	.set = param_set_aabool,
	.get = param_get_aabool
};

static int param_set_aauint(const char *val, const struct kernel_param *kp);
static int param_get_aauint(char *buffer, const struct kernel_param *kp);
#define param_check_aauint param_check_uint
static const struct kernel_param_ops param_ops_aauint = {
	.set = param_set_aauint,
	.get = param_get_aauint
};

static int param_set_aalockpolicy(const char *val, const struct kernel_param *kp);
static int param_get_aalockpolicy(char *buffer, const struct kernel_param *kp);
#define param_check_aalockpolicy param_check_bool
static const struct kernel_param_ops param_ops_aalockpolicy = {
	.flags = KERNEL_PARAM_OPS_FL_NOARG,
	.set = param_set_aalockpolicy,
	.get = param_get_aalockpolicy
};

static int param_set_audit(const char *val, const struct kernel_param *kp);
static int param_get_audit(char *buffer, const struct kernel_param *kp);

static int param_set_mode(const char *val, const struct kernel_param *kp);
static int param_get_mode(char *buffer, const struct kernel_param *kp);

/* Flag values, also controllable via /sys/module/apparmor/parameters
 * We define special types as we want to do additional mediation.
 */

/* AppArmor global enforcement switch - complain, enforce, kill */
enum profile_mode aa_g_profile_mode = APPARMOR_ENFORCE;
module_param_call(mode, param_set_mode, param_get_mode,
		  &aa_g_profile_mode, S_IRUSR | S_IWUSR);

/* whether policy verification hashing is enabled */
bool aa_g_hash_policy = IS_ENABLED(CONFIG_SECURITY_APPARMOR_HASH_DEFAULT);
#ifdef CONFIG_SECURITY_APPARMOR_HASH
module_param_named(hash_policy, aa_g_hash_policy, aabool, S_IRUSR | S_IWUSR);
#endif

/* Debug mode */
bool aa_g_debug = IS_ENABLED(CONFIG_SECURITY_APPARMOR_DEBUG_MESSAGES);
module_param_named(debug, aa_g_debug, aabool, S_IRUSR | S_IWUSR);

/* Audit mode */
enum audit_mode aa_g_audit;
module_param_call(audit, param_set_audit, param_get_audit,
		  &aa_g_audit, S_IRUSR | S_IWUSR);

/* Determines if audit header is included in audited messages.  This
 * provides more context if the audit daemon is not running
 */
bool aa_g_audit_header = true;
module_param_named(audit_header, aa_g_audit_header, aabool,
		   S_IRUSR | S_IWUSR);

/* lock out loading/removal of policy
 * TODO: add in at boot loading of policy, which is the only way to
 *       load policy, if lock_policy is set
 */
bool aa_g_lock_policy;
module_param_named(lock_policy, aa_g_lock_policy, aalockpolicy,
		   S_IRUSR | S_IWUSR);

/* Syscall logging mode */
bool aa_g_logsyscall;
module_param_named(logsyscall, aa_g_logsyscall, aabool, S_IRUSR | S_IWUSR);

/* Maximum pathname length before accesses will start getting rejected */
unsigned int aa_g_path_max = 2 * PATH_MAX;
module_param_named(path_max, aa_g_path_max, aauint, S_IRUSR);

/* Determines how paranoid loading of policy is and how much verification
 * on the loaded policy is done.
 * DEPRECATED: read only as strict checking of load is always done now
 * that none root users (user namespaces) can load policy.
 */
bool aa_g_paranoid_load = true;
module_param_named(paranoid_load, aa_g_paranoid_load, aabool, S_IRUGO);

static int param_get_aaintbool(char *buffer, const struct kernel_param *kp);
static int param_set_aaintbool(const char *val, const struct kernel_param *kp);
#define param_check_aaintbool param_check_int
static const struct kernel_param_ops param_ops_aaintbool = {
	.set = param_set_aaintbool,
	.get = param_get_aaintbool
};
/* Boot time disable flag */
static int apparmor_enabled __lsm_ro_after_init = 1;
module_param_named(enabled, apparmor_enabled, aaintbool, 0444);

static int __init apparmor_enabled_setup(char *str)
{
	unsigned long enabled;
	int error = kstrtoul(str, 0, &enabled);
	if (!error)
		apparmor_enabled = enabled ? 1 : 0;
	return 1;
}

__setup("apparmor=", apparmor_enabled_setup);

/* set global flag turning off the ability to load policy */
static int param_set_aalockpolicy(const char *val, const struct kernel_param *kp)
{
	if (!apparmor_enabled)
		return -EINVAL;
	if (apparmor_initialized && !policy_admin_capable(NULL))
		return -EPERM;
	return param_set_bool(val, kp);
}

static int param_get_aalockpolicy(char *buffer, const struct kernel_param *kp)
{
	if (!apparmor_enabled)
		return -EINVAL;
	if (apparmor_initialized && !policy_view_capable(NULL))
		return -EPERM;
	return param_get_bool(buffer, kp);
}

static int param_set_aabool(const char *val, const struct kernel_param *kp)
{
	if (!apparmor_enabled)
		return -EINVAL;
	if (apparmor_initialized && !policy_admin_capable(NULL))
		return -EPERM;
	return param_set_bool(val, kp);
}

static int param_get_aabool(char *buffer, const struct kernel_param *kp)
{
	if (!apparmor_enabled)
		return -EINVAL;
	if (apparmor_initialized && !policy_view_capable(NULL))
		return -EPERM;
	return param_get_bool(buffer, kp);
}

static int param_set_aauint(const char *val, const struct kernel_param *kp)
{
	int error;

	if (!apparmor_enabled)
		return -EINVAL;
	/* file is ro but enforce 2nd line check */
	if (apparmor_initialized)
		return -EPERM;

	error = param_set_uint(val, kp);
	pr_info("AppArmor: buffer size set to %d bytes\n", aa_g_path_max);

	return error;
}

static int param_get_aauint(char *buffer, const struct kernel_param *kp)
{
	if (!apparmor_enabled)
		return -EINVAL;
	if (apparmor_initialized && !policy_view_capable(NULL))
		return -EPERM;
	return param_get_uint(buffer, kp);
}

/* Can only be set before AppArmor is initialized (i.e. on boot cmdline). */
static int param_set_aaintbool(const char *val, const struct kernel_param *kp)
{
	struct kernel_param kp_local;
	bool value;
	int error;

	if (apparmor_initialized)
		return -EPERM;

	/* Create local copy, with arg pointing to bool type. */
	value = !!*((int *)kp->arg);
	memcpy(&kp_local, kp, sizeof(kp_local));
	kp_local.arg = &value;

	error = param_set_bool(val, &kp_local);
	if (!error)
		*((int *)kp->arg) = *((bool *)kp_local.arg);
	return error;
}

/*
 * To avoid changing /sys/module/apparmor/parameters/enabled from Y/N to
 * 1/0, this converts the "int that is actually bool" back to bool for
 * display in the /sys filesystem, while keeping it "int" for the LSM
 * infrastructure.
 */
static int param_get_aaintbool(char *buffer, const struct kernel_param *kp)
{
	struct kernel_param kp_local;
	bool value;

	/* Create local copy, with arg pointing to bool type. */
	value = !!*((int *)kp->arg);
	memcpy(&kp_local, kp, sizeof(kp_local));
	kp_local.arg = &value;

	return param_get_bool(buffer, &kp_local);
}

static int param_get_audit(char *buffer, const struct kernel_param *kp)
{
	if (!apparmor_enabled)
		return -EINVAL;
	if (apparmor_initialized && !policy_view_capable(NULL))
		return -EPERM;
	return sprintf(buffer, "%s", audit_mode_names[aa_g_audit]);
}

static int param_set_audit(const char *val, const struct kernel_param *kp)
{
	int i;

	if (!apparmor_enabled)
		return -EINVAL;
	if (!val)
		return -EINVAL;
	if (apparmor_initialized && !policy_admin_capable(NULL))
		return -EPERM;

	i = match_string(audit_mode_names, AUDIT_MAX_INDEX, val);
	if (i < 0)
		return -EINVAL;

	aa_g_audit = i;
	return 0;
}

static int param_get_mode(char *buffer, const struct kernel_param *kp)
{
	if (!apparmor_enabled)
		return -EINVAL;
	if (apparmor_initialized && !policy_view_capable(NULL))
		return -EPERM;

	return sprintf(buffer, "%s", aa_profile_mode_names[aa_g_profile_mode]);
}

static int param_set_mode(const char *val, const struct kernel_param *kp)
{
	int i;

	if (!apparmor_enabled)
		return -EINVAL;
	if (!val)
		return -EINVAL;
	if (apparmor_initialized && !policy_admin_capable(NULL))
		return -EPERM;

	i = match_string(aa_profile_mode_names, APPARMOR_MODE_NAMES_MAX_INDEX,
			 val);
	if (i < 0)
		return -EINVAL;

	aa_g_profile_mode = i;
	return 0;
}

/*
 * AppArmor init functions
 */

/**
 * set_init_ctx - set a task context and profile on the first task.
 *
 * TODO: allow setting an alternate profile than unconfined
 */
static int __init set_init_ctx(void)
{
	struct cred *cred = (struct cred *)current->real_cred;

	set_cred_label(cred, aa_get_label(ns_unconfined(root_ns)));

	return 0;
}

static void destroy_buffers(void)
{
	u32 i, j;

	for_each_possible_cpu(i) {
		for_each_cpu_buffer(j) {
			kfree(per_cpu(aa_buffers, i).buf[j]);
			per_cpu(aa_buffers, i).buf[j] = NULL;
		}
	}
}

static int __init alloc_buffers(void)
{
	u32 i, j;

	for_each_possible_cpu(i) {
		for_each_cpu_buffer(j) {
			char *buffer;

			if (cpu_to_node(i) > num_online_nodes())
				/* fallback to kmalloc for offline nodes */
				buffer = kmalloc(aa_g_path_max, GFP_KERNEL);
			else
				buffer = kmalloc_node(aa_g_path_max, GFP_KERNEL,
						      cpu_to_node(i));
			if (!buffer) {
				destroy_buffers();
				return -ENOMEM;
			}
			per_cpu(aa_buffers, i).buf[j] = buffer;
		}
	}

	return 0;
}

#ifdef CONFIG_SYSCTL
static int apparmor_dointvec(struct ctl_table *table, int write,
			     void __user *buffer, size_t *lenp, loff_t *ppos)
{
	if (!policy_admin_capable(NULL))
		return -EPERM;
	if (!apparmor_enabled)
		return -EINVAL;

	return proc_dointvec(table, write, buffer, lenp, ppos);
}

static struct ctl_path apparmor_sysctl_path[] = {
	{ .procname = "kernel", },
	{ }
};

static struct ctl_table apparmor_sysctl_table[] = {
	{
		.procname       = "unprivileged_userns_apparmor_policy",
		.data           = &unprivileged_userns_apparmor_policy,
		.maxlen         = sizeof(int),
		.mode           = 0600,
		.proc_handler   = apparmor_dointvec,
	},
	{ }
};

static int __init apparmor_init_sysctl(void)
{
	return register_sysctl_paths(apparmor_sysctl_path,
				     apparmor_sysctl_table) ? 0 : -ENOMEM;
}
#else
static inline int apparmor_init_sysctl(void)
{
	return 0;
}
#endif /* CONFIG_SYSCTL */

#if defined(CONFIG_NETFILTER) && defined(CONFIG_NETWORK_SECMARK)
static unsigned int apparmor_ip_postroute(void *priv,
					  struct sk_buff *skb,
					  const struct nf_hook_state *state)
{
	struct aa_sk_ctx *ctx;
	struct sock *sk;

	if (!skb->secmark)
		return NF_ACCEPT;

	sk = skb_to_full_sk(skb);
	if (sk == NULL)
		return NF_ACCEPT;

	ctx = SK_CTX(sk);
	if (!apparmor_secmark_check(ctx->label, OP_SENDMSG, AA_MAY_SEND,
				    skb->secmark, sk))
		return NF_ACCEPT;

	return NF_DROP_ERR(-ECONNREFUSED);

}

static unsigned int apparmor_ipv4_postroute(void *priv,
					    struct sk_buff *skb,
					    const struct nf_hook_state *state)
{
	return apparmor_ip_postroute(priv, skb, state);
}

static unsigned int apparmor_ipv4_output(void *priv,
					 struct sk_buff *skb,
					 const struct nf_hook_state *state)
{
	const struct iphdr *ip;	

	ip = ip_hdr(skb);
	if(ip->protocol == IPPROTO_IGMP)
	{
		// printk(KERN_INFO "NF_OUTPUT: IGMP protocol allowed -> %d\n", ip->protocol);
	}
	return NF_ACCEPT;
}

#if IS_ENABLED(CONFIG_IPV6)
static unsigned int apparmor_ipv6_postroute(void *priv,
					    struct sk_buff *skb,
					    const struct nf_hook_state *state)
{
	return apparmor_ip_postroute(priv, skb, state);
}
#endif

static const struct nf_hook_ops apparmor_nf_ops[] = {
	{
		.hook =         apparmor_ipv4_postroute,
		.pf =           NFPROTO_IPV4,
		.hooknum =      NF_INET_POST_ROUTING,
		.priority =     NF_IP_PRI_SELINUX_FIRST,
	},
	{
		.hook =		apparmor_ipv4_output,
		.pf =		NFPROTO_IPV4,
		.hooknum =	NF_INET_LOCAL_OUT,
		.priority =	NF_IP_PRI_FIRST,
	},
#if IS_ENABLED(CONFIG_IPV6)
	{
		.hook =         apparmor_ipv6_postroute,
		.pf =           NFPROTO_IPV6,
		.hooknum =      NF_INET_POST_ROUTING,
		.priority =     NF_IP6_PRI_SELINUX_FIRST,
	},
#endif
};

static int __net_init apparmor_nf_register(struct net *net)
{
	int ret;

	ret = nf_register_net_hooks(net, apparmor_nf_ops,
				    ARRAY_SIZE(apparmor_nf_ops));
	return ret;
}

static void __net_exit apparmor_nf_unregister(struct net *net)
{
	nf_unregister_net_hooks(net, apparmor_nf_ops,
				ARRAY_SIZE(apparmor_nf_ops));
}

static struct pernet_operations apparmor_net_ops = {
	.init = apparmor_nf_register,
	.exit = apparmor_nf_unregister,
};

static int __init apparmor_nf_ip_init(void)
{
	int err;

	if (!apparmor_enabled)
		return 0;

	err = register_pernet_subsys(&apparmor_net_ops);
	if (err)
		panic("Apparmor: register_pernet_subsys: error %d\n", err);

	return 0;
}
__initcall(apparmor_nf_ip_init);
#endif

static int __init apparmor_init(void)
{
	int error;

	aa_secids_init();

	error = aa_setup_dfa_engine();
	if (error) {
		AA_ERROR("Unable to setup dfa engine\n");
		goto alloc_out;
	}

	error = aa_alloc_root_ns();
	if (error) {
		AA_ERROR("Unable to allocate default profile namespace\n");
		goto alloc_out;
	}

	error = apparmor_init_sysctl();
	if (error) {
		AA_ERROR("Unable to register sysctls\n");
		goto alloc_out;

	}

	error = alloc_buffers();
	if (error) {
		AA_ERROR("Unable to allocate work buffers\n");
		goto buffers_out;
	}

	error = set_init_ctx();
	if (error) {
		AA_ERROR("Failed to set context on init task\n");
		aa_free_root_ns();
		goto buffers_out;
	}
	security_add_hooks(apparmor_hooks, ARRAY_SIZE(apparmor_hooks),
				"apparmor");

	/* Report that AppArmor successfully initialized */
	apparmor_initialized = 1;
	if (aa_g_profile_mode == APPARMOR_COMPLAIN)
		aa_info_message("AppArmor initialized: complain mode enabled");
	else if (aa_g_profile_mode == APPARMOR_KILL)
		aa_info_message("AppArmor initialized: kill mode enabled");
	else
		aa_info_message("AppArmor initialized");

	return error;

buffers_out:
	destroy_buffers();

alloc_out:
	aa_destroy_aafs();
	aa_teardown_dfa_engine();

	apparmor_enabled = false;
	return error;
}

DEFINE_LSM(apparmor) = {
	.name = "apparmor",
	.flags = LSM_FLAG_LEGACY_MAJOR | LSM_FLAG_EXCLUSIVE,
	.enabled = &apparmor_enabled,
	.blobs = &apparmor_blob_sizes,
	.init = apparmor_init,
};





long apparmor_debug_flag_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
	switch(cmd)
	{
		case SET_FLAG:

			// printk_ratelimited(KERN_INFO "debug_flag: set\n");
			apparmor_ioctl_debug = 1;
			break;
		
		case CLEAR_FLAG:

			// printk_ratelimited(KERN_INFO "debug_flag: clear\n");
			apparmor_ioctl_debug = 0;
			break;
		
		// case SET_KERNEL_FLAG:

		// 	// printk_ratelimited(KERN_INFO "debug_flag: set\n");
		// 	global_kernel_debug_flag = 1;
		// 	break;
		// case CLEAR_KERNEL_FLAG:

		// 	// printk_ratelimited(KERN_INFO "CLEAR_KERNEL_FLAG: set\n");
		// 	global_kernel_debug_flag = 0;
		// 	break;
		
	}

	return 0;
}

int apparmor_debug_flag_open(struct inode *i, struct file *f)
{
	printk_ratelimited(KERN_INFO "debug_flag: Opening device by process %ld\n", (long)(current -> pid));
    return 0;
}

int apparmor_debug_flag_close(struct inode *i, struct file *f)
{
	printk_ratelimited(KERN_INFO "debug_flag: Closing device by process %ld\n", (long)(current -> pid));
    return 0;
}

/*
 * Map the file operation function pointers to the custom implementations
 */
static struct file_operations apparmor_debug_flag_fops = {

	.unlocked_ioctl = apparmor_debug_flag_ioctl,
	.open = apparmor_debug_flag_open,
	.release = apparmor_debug_flag_close,
};


/*
 * Set device parameters
 */
static struct miscdevice apparmor_debug_flag_device_ops = {

	.minor = MISC_DYNAMIC_MINOR,
	.name = "debug_flag",
	.fops = &apparmor_debug_flag_fops,
};

int __init apparmor_debug_flag_init(void)
{
	int ret;
    ret = misc_register(&apparmor_debug_flag_device_ops);
	if(ret < 0)
	{
		printk_ratelimited(KERN_INFO "debug_flag device registration failed with %d\n", ret);
	}
	else
	{
		printk_ratelimited(KERN_INFO "debug_flag device successfully registered\n");
	}
    return ret;
}

device_initcall(apparmor_debug_flag_init);