/*
 * AppArmor security module
 *
 * This file contains AppArmor LSM hooks.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
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
#include <net/sock.h>

#include "include/apparmor.h"
#include "include/apparmorfs.h"
#include "include/audit.h"
#include "include/capability.h"
#include "include/context.h"
#include "include/file.h"
#include "include/ipc.h"
#include "include/path.h"
#include "include/policy.h"
#include "include/procattr.h"


#include <net/af_unix.h>
#include <linux/skbuff.h>
#include <net/inet_sock.h>
#include <linux/inetdevice.h>
#include <linux/tcp.h>
#include <uapi/linux/tcp.h>


/* Flag indicating whether initialization completed */
int apparmor_initialized __initdata;



#define MAX_LABEL_CACHE_SIZE 20
struct profile_cache
{
	pid_t pid;
	struct aa_profile *cur_profile;

}profile_cache_arr[MAX_LABEL_CACHE_SIZE];

static int apparmor_tsk_container_add(struct aa_profile *profile, pid_t pid)
{
	int ret = 0, i;
	static int remove_idx = 0;
	for(i = 0; i < MAX_LABEL_CACHE_SIZE; i++)
	{
		if(profile_cache_arr[i].pid == pid)
		{
			ret = 1;
			break;
		}
		else if (profile_cache_arr[i].pid == 0)
		{
			profile_cache_arr[i].pid = pid;
			profile_cache_arr[i].cur_profile = aa_get_profile(profile);
			ret = 1;
			break;
		}
	}
	if (ret == 0)
	{
		// printk (KERN_INFO "apparmor_tsk_container_add: adding data at idx %d, pid %d, profile %s\n", remove_idx, pid, profile->hname);
		
		profile_cache_arr[remove_idx].pid = pid;
		profile_cache_arr[remove_idx].cur_profile = aa_get_profile(profile);
		remove_idx += 1;
		remove_idx %= MAX_LABEL_CACHE_SIZE;
	}
	else
	{
		// printk (KERN_INFO "apparmor_tsk_container_add: adding data at idx %d, pid %d, profile %s\n", i, pid, profile->hname);
	}
	
	return ret;	
}

static struct aa_profile *apparmor_tsk_container_get(pid_t pid)
{
	struct aa_profile *ret = NULL;
	int i;
	for(i = 0; i < MAX_LABEL_CACHE_SIZE; i++)
	{
		if (profile_cache_arr[i].pid == pid && profile_cache_arr[i].cur_profile != NULL)
		{
			ret = aa_get_profile(profile_cache_arr[i].cur_profile);
			break;
		}
	}
	if (ret != NULL)
	{
		printk (KERN_INFO "apparmor_tsk_container_get: data found at idx %d, pid %d, profile %s\n", i, pid, ret->base.hname);
	}
	else
	{
		printk (KERN_INFO "apparmor_tsk_container_get: data not found for pid %d\n", pid);
	}
	return ret;
}

static int apparmor_tsk_container_remove(pid_t pid)
{
	int ret = 0, i;
	for(i = 0; i < MAX_LABEL_CACHE_SIZE; i++)
	{
		if(profile_cache_arr[i].pid == pid)
		{
			// printk (KERN_INFO "apparmor_tsk_container_get: data removed at idx %d, pid %d, profile %s\n", i, pid, profile_cache_arr[i].cur_profile->base.hname);
			profile_cache_arr[i].pid = 0;
			aa_put_profile(profile_cache_arr[i].cur_profile);

			profile_cache_arr[i].cur_profile = NULL;
			ret = 1;
		}
	}
	return ret;	
}
static int apparmor_extract_daddr(struct msghdr *msg, struct sock *sk)
{
	struct inet_sock *inet;
	u32 daddr = 0;
	DECLARE_SOCKADDR(struct sockaddr_in *, usin, msg->msg_name);
	inet = inet_sk(sk);
		
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

static bool apparmor_check_for_flow (struct aa_profile *profile, char *checking_domain)
{
	struct ListOfDomains *iterator;
	if (profile->allow_net_domains)
	{
		list_for_each_entry(iterator, &(profile->allow_net_domains->domain_list), domain_list)
		{
			printk (KERN_INFO "apparmor_check_for_flow: Matching between %s, %s\n", iterator->domain, checking_domain);
			if ((strcmp(iterator->domain, checking_domain) == 0) || strcmp(iterator->domain, "*") == 0)
			{
				return true;
			}
		}
	}
	return false;
}

static struct aa_profile *apparmor_socket_label_compare_helper(__u32 pid)
{
	struct task_struct *task_data;
	struct aa_profile *ret = NULL;
	task_data = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
	if (task_data == NULL)
	{
		ret = apparmor_tsk_container_get(pid);
	}
	else
	{
		ret = aa_cred_profile(__task_cred(task_data));
	}
	return ret;
}
static bool apparmor_socket_label_compare(__u32 sender_pid, __u32 receiver_pid)
{
	bool allow = false;		
	struct aa_profile *sender_profile, *receiver_profile;
	char *receiver_domain = NULL;
	
	if (sender_pid != receiver_pid && sender_pid != 0 && receiver_pid != 0)
	{
		sender_profile = apparmor_socket_label_compare_helper(sender_pid);
		receiver_profile = apparmor_socket_label_compare_helper(receiver_pid);
		
		if (sender_profile != NULL && receiver_profile != NULL)
		{
			if (receiver_profile->current_domain != NULL && receiver_profile->current_domain->domain != NULL)
			{
				receiver_domain = receiver_profile->current_domain->domain;
			}
			if (receiver_domain != NULL)
			{
				allow = apparmor_check_for_flow(sender_profile, receiver_domain);
				if (allow)
				{
					printk (KERN_INFO "[GRAPH_GEN] Process %s, socket_ipc, %s\n", sender_profile->base.hname, receiver_profile->base.hname);
				}
				
			}
			
			printk (KERN_INFO "apparmor_socket_label_compare: receiver process = %s, pid = %d, sent from process %s, pid = %d, Match is %d\n", receiver_profile->base.hname, receiver_pid, sender_profile->base.hname, sender_pid, allow);
		
		}
		
	}
	return allow;
}

static bool apparmor_domain_declassify (struct aa_profile *profile, u32 check_ip_addr)
{
	struct ListOfIPAddrs *iterator;
	if (profile->allowed_ip_addrs)
	{
		list_for_each_entry(iterator, &(profile->allowed_ip_addrs->ip_addr_list), ip_addr_list)
		{
			// printk (KERN_INFO "apparmor_domain_declassify: Matching between %u, %u\n", iterator->ip_addr, check_ip_addr);
			if (iterator->ip_addr == 0 || iterator->ip_addr == check_ip_addr)
			{
				return true;
			}
		}
	}
	return false;
}


/*
 * LSM hook functions
 */

/*
 * free the associated aa_task_cxt and put its profiles
 */
static void apparmor_cred_free(struct cred *cred)
{
	aa_free_task_context(cred_cxt(cred));
	cred_cxt(cred) = NULL;
}

/*
 * allocate the apparmor part of blank credentials
 */
static int apparmor_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	/* freed by apparmor_cred_free */
	struct aa_task_cxt *cxt = aa_alloc_task_context(gfp);
	if (!cxt)
		return -ENOMEM;

	cred_cxt(cred) = cxt;
	return 0;
}

/*
 * prepare new aa_task_cxt for modification by prepare_cred block
 */
static int apparmor_cred_prepare(struct cred *new, const struct cred *old,
				 gfp_t gfp)
{
	/* freed by apparmor_cred_free */
	struct aa_task_cxt *cxt = aa_alloc_task_context(gfp);
	if (!cxt)
		return -ENOMEM;

	aa_dup_task_context(cxt, cred_cxt(old));
	cred_cxt(new) = cxt;
	return 0;
}

/*
 * transfer the apparmor data to a blank set of creds
 */
static void apparmor_cred_transfer(struct cred *new, const struct cred *old)
{
	const struct aa_task_cxt *old_cxt = cred_cxt(old);
	struct aa_task_cxt *new_cxt = cred_cxt(new);

	aa_dup_task_context(new_cxt, old_cxt);
}

static int apparmor_ptrace_access_check(struct task_struct *child,
					unsigned int mode)
{
	return aa_ptrace(current, child, mode);
}

static int apparmor_ptrace_traceme(struct task_struct *parent)
{
	return aa_ptrace(parent, current, PTRACE_MODE_ATTACH);
}

/* Derived from security/commoncap.c:cap_capget */
static int apparmor_capget(struct task_struct *target, kernel_cap_t *effective,
			   kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	struct aa_profile *profile;
	const struct cred *cred;

	rcu_read_lock();
	cred = __task_cred(target);
	profile = aa_cred_profile(cred);

	/*
	 * cap_capget is stacked ahead of this and will
	 * initialize effective and permitted.
	 */
	if (!unconfined(profile) && !COMPLAIN_MODE(profile)) {
		*effective = cap_intersect(*effective, profile->caps.allow);
		*permitted = cap_intersect(*permitted, profile->caps.allow);
	}
	rcu_read_unlock();

	return 0;
}

static int apparmor_capable(const struct cred *cred, struct user_namespace *ns,
			    int cap, int audit)
{
	struct aa_profile *profile;
	int error = 0;

	profile = aa_cred_profile(cred);
	if (!unconfined(profile))
		error = aa_capable(profile, cap, audit);
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
static int common_perm(int op, const struct path *path, u32 mask,
		       struct path_cond *cond)
{
	struct aa_profile *profile;
	int error = 0;

	profile = __aa_current_profile();
	if (!unconfined(profile))
		error = aa_path_perm(op, profile, path, 0, mask, cond);

	return error;
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
static int common_perm_dir_dentry(int op, const struct path *dir,
				  struct dentry *dentry, u32 mask,
				  struct path_cond *cond)
{
	struct path path = { dir->mnt, dentry };

	return common_perm(op, &path, mask, cond);
}

/**
 * common_perm_path - common permission wrapper when mnt, dentry
 * @op: operation being checked
 * @path: location to check (NOT NULL)
 * @mask: requested permissions mask
 *
 * Returns: %0 else error code if error or permission denied
 */
static inline int common_perm_path(int op, const struct path *path, u32 mask)
{
	struct path_cond cond = { d_backing_inode(path->dentry)->i_uid,
				  d_backing_inode(path->dentry)->i_mode
	};
	if (!mediated_filesystem(path->dentry))
		return 0;

	return common_perm(op, path, mask, &cond);
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
static int common_perm_rm(int op, const struct path *dir,
			  struct dentry *dentry, u32 mask)
{
	struct inode *inode = d_backing_inode(dentry);
	struct path_cond cond = { };

	if (!inode || !mediated_filesystem(dentry))
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
static int common_perm_create(int op, const struct path *dir,
			      struct dentry *dentry, u32 mask, umode_t mode)
{
	struct path_cond cond = { current_fsuid(), mode };

	if (!mediated_filesystem(dir->dentry))
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
	return common_perm_path(OP_TRUNC, path, MAY_WRITE | AA_MAY_META_WRITE);
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
	struct aa_profile *profile;
	int error = 0;

	if (!mediated_filesystem(old_dentry))
		return 0;

	profile = aa_current_profile();
	if (!unconfined(profile))
		error = aa_path_link(profile, old_dentry, new_dir, new_dentry);
	return error;
}

static int apparmor_path_rename(const struct path *old_dir, struct dentry *old_dentry,
				const struct path *new_dir, struct dentry *new_dentry)
{
	struct aa_profile *profile;
	int error = 0;

	if (!mediated_filesystem(old_dentry))
		return 0;

	profile = aa_current_profile();
	if (!unconfined(profile)) {
		struct path old_path = { old_dir->mnt, old_dentry };
		struct path new_path = { new_dir->mnt, new_dentry };
		struct path_cond cond = { d_backing_inode(old_dentry)->i_uid,
					  d_backing_inode(old_dentry)->i_mode
		};

		error = aa_path_perm(OP_RENAME_SRC, profile, &old_path, 0,
				     MAY_READ | AA_MAY_META_READ | MAY_WRITE |
				     AA_MAY_META_WRITE | AA_MAY_DELETE,
				     &cond);
		if (!error)
			error = aa_path_perm(OP_RENAME_DEST, profile, &new_path,
					     0, MAY_WRITE | AA_MAY_META_WRITE |
					     AA_MAY_CREATE, &cond);

	}
	return error;
}

static int apparmor_path_chmod(const struct path *path, umode_t mode)
{
	return common_perm_path(OP_CHMOD, path, AA_MAY_CHMOD);
}

static int apparmor_path_chown(const struct path *path, kuid_t uid, kgid_t gid)
{
	return common_perm_path(OP_CHOWN, path, AA_MAY_CHOWN);
}

static int apparmor_inode_getattr(const struct path *path)
{
	return common_perm_path(OP_GETATTR, path, AA_MAY_META_READ);
}

static int apparmor_file_open(struct file *file, const struct cred *cred)
{
	struct aa_file_cxt *fcxt = file->f_security;
	struct aa_profile *profile;
	int error = 0;

	if (!mediated_filesystem(file->f_path.dentry))
		return 0;

	/* If in exec, permission is handled by bprm hooks.
	 * Cache permissions granted by the previous exec check, with
	 * implicit read and executable mmap which are required to
	 * actually execute the image.
	 */
	if (current->in_execve) {
		fcxt->allow = MAY_EXEC | MAY_READ | AA_EXEC_MMAP;
		return 0;
	}

	profile = aa_cred_profile(cred);
	if (!unconfined(profile)) {
		struct inode *inode = file_inode(file);
		struct path_cond cond = { inode->i_uid, inode->i_mode };

		error = aa_path_perm(OP_OPEN, profile, &file->f_path, 0,
				     aa_map_file_to_perms(file), &cond);
		/* todo cache full allowed permissions set and state */
		fcxt->allow = aa_map_file_to_perms(file);
	}

	return error;
}

static int apparmor_file_alloc_security(struct file *file)
{
	/* freed by apparmor_file_free_security */
	file->f_security = aa_alloc_file_context(GFP_KERNEL);
	if (!file->f_security)
		return -ENOMEM;
	return 0;

}

static void apparmor_file_free_security(struct file *file)
{
	struct aa_file_cxt *cxt = file->f_security;

	aa_free_file_context(cxt);
}

static int common_file_perm(int op, struct file *file, u32 mask)
{
	struct aa_file_cxt *fcxt = file->f_security;
	struct aa_profile *profile, *fprofile = aa_cred_profile(file->f_cred);
	int error = 0;

	BUG_ON(!fprofile);

	if (!file->f_path.mnt ||
	    !mediated_filesystem(file->f_path.dentry))
		return 0;

	profile = __aa_current_profile();

	/* revalidate access, if task is unconfined, or the cached cred
	 * doesn't match or if the request is for more permissions than
	 * was granted.
	 *
	 * Note: the test for !unconfined(fprofile) is to handle file
	 *       delegation from unconfined tasks
	 */
	if (!unconfined(profile) && !unconfined(fprofile) &&
	    ((fprofile != profile) || (mask & ~fcxt->allow)))
		error = aa_file_perm(op, profile, file, mask);

	return error;
}

static int apparmor_file_permission(struct file *file, int mask)
{
	return common_file_perm(OP_FPERM, file, mask);
}

static int apparmor_file_lock(struct file *file, unsigned int cmd)
{
	u32 mask = AA_MAY_LOCK;

	if (cmd == F_WRLCK)
		mask |= MAY_WRITE;

	return common_file_perm(OP_FLOCK, file, mask);
}

static int common_mmap(int op, struct file *file, unsigned long prot,
		       unsigned long flags)
{
	int mask = 0;

	if (!file || !file->f_security)
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

static int apparmor_getprocattr(struct task_struct *task, char *name,
				char **value)
{
	int error = -ENOENT;
	/* released below */
	const struct cred *cred = get_task_cred(task);
	struct aa_task_cxt *cxt = cred_cxt(cred);
	struct aa_profile *profile = NULL;

	if (strcmp(name, "current") == 0)
		profile = aa_get_newest_profile(cxt->profile);
	else if (strcmp(name, "prev") == 0  && cxt->previous)
		profile = aa_get_newest_profile(cxt->previous);
	else if (strcmp(name, "exec") == 0 && cxt->onexec)
		profile = aa_get_newest_profile(cxt->onexec);
	else
		error = -EINVAL;

	if (profile)
		error = aa_getprocattr(profile, value);

	aa_put_profile(profile);
	put_cred(cred);

	return error;
}

static int apparmor_setprocattr(struct task_struct *task, char *name,
				void *value, size_t size)
{
	struct common_audit_data sa;
	struct apparmor_audit_data aad = {0,};
	char *command, *largs = NULL, *args = value;
	size_t arg_size;
	int error;

	if (size == 0)
		return -EINVAL;
	/* task can only write its own attributes */
	if (current != task)
		return -EACCES;

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
							 !AA_DO_TEST);
		} else if (strcmp(command, "permhat") == 0) {
			error = aa_setprocattr_changehat(args, arg_size,
							 AA_DO_TEST);
		} else if (strcmp(command, "changeprofile") == 0) {
			error = aa_setprocattr_changeprofile(args, !AA_ONEXEC,
							     !AA_DO_TEST);
		} else if (strcmp(command, "permprofile") == 0) {
			error = aa_setprocattr_changeprofile(args, !AA_ONEXEC,
							     AA_DO_TEST);
		} else
			goto fail;
	} else if (strcmp(name, "exec") == 0) {
		if (strcmp(command, "exec") == 0)
			error = aa_setprocattr_changeprofile(args, AA_ONEXEC,
							     !AA_DO_TEST);
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
	sa.type = LSM_AUDIT_DATA_NONE;
	sa.aad = &aad;
	aad.profile = aa_current_profile();
	aad.op = OP_SETPROCATTR;
	aad.info = name;
	aad.error = error = -EINVAL;
	aa_audit_msg(AUDIT_APPARMOR_DENIED, &sa, NULL);
	goto out;
}

static int apparmor_task_setrlimit(struct task_struct *task,
		unsigned int resource, struct rlimit *new_rlim)
{
	struct aa_profile *profile = __aa_current_profile();
	int error = 0;

	if (!unconfined(profile))
		error = aa_task_setrlimit(profile, task, resource, new_rlim);

	return error;
}


static int apparmor_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
{
	struct aa_sk_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	SK_CTX(sk) = ctx;

	return 0;
}

static void apparmor_sk_free_security(struct sock *sk)
{
	struct aa_sk_ctx *ctx = SK_CTX(sk);

	SK_CTX(sk) = NULL;
	aa_put_profile(ctx->profile);
	kfree(ctx);	
}


static void apparmor_sk_clone_security(const struct sock *sk, struct sock *newsk)
{
	struct aa_sk_ctx *ctx = SK_CTX(sk);
	struct aa_sk_ctx *new = SK_CTX(newsk);

	new->profile = aa_get_profile(ctx->profile);
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
	struct aa_profile *profile;

	if (kern) {
		// struct aa_ns *ns = aa_get_current_ns();

		// label = aa_get_label(ns_unconfined(ns));
		// aa_put_ns(ns);

		struct aa_namespace *ns = aa_get_namespace((aa_current_profile())->ns);
		profile = aa_get_profile(ns->unconfined);
		aa_put_namespace(ns);

	} else
		profile = aa_get_task_profile(current);

	if (sock->sk) {
		struct aa_sk_ctx *ctx = SK_CTX(sock->sk);

		aa_put_profile(ctx->profile);
		ctx->profile = aa_get_profile(profile);
	}
	aa_put_profile(profile);

	return 0;
}



/**
 * apparmor_socket_sendmsg - check perms before sending msg to another socket
 */
static int apparmor_socket_sendmsg(struct socket *sock,
				   struct msghdr *msg, int size)
{
	struct sock *sk = sock->sk;
    struct aa_profile *curr_profile;
    struct aa_profile *curr_sock_profile;
    struct aa_sk_ctx *ctx = SK_CTX(sk);
    char *curr_domain = NULL;
	bool allow = false;
    u32 daddr = 0;
	
	curr_profile = aa_get_task_profile(current);	
	if(curr_profile != NULL && !unconfined(curr_profile) && ctx != NULL && ctx->profile != NULL)
	{
		printk(KERN_INFO "sendmsg: process %s, label: %s\n", current->comm, curr_profile->base.hname);
		curr_sock_profile = aa_get_profile(ctx->profile);
		
		//reset the recv_pid
		if (curr_sock_profile->pid != current->pid)
		{
			curr_sock_profile->recv_pid = 0;
		}
		curr_sock_profile->pid = current->pid;

		//get the domain from current process profile and not from socket's profile, coz socket's can be passed
		if(curr_profile->current_domain != NULL && curr_profile->current_domain->domain != NULL)
        {
            curr_domain = curr_profile->current_domain->domain;
        }
		
		if (curr_domain != NULL)
		{
			apparmor_tsk_container_add(curr_profile, current->pid);
			// printk (KERN_INFO "apparmor_socket_sendmsg (%s): current_pid = %d, sk_family=%d, sock->type=%d\n", current->comm, current->pid, sock->sk->sk_family, sock->type);
			if(sk->sk_family == AF_INET)
			{   
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
					allow = true;
					// printk(KERN_INFO "apparmor_socket_sendmsg (%s): Packet from localhost to localhost allowed, current_pid = %d\n", current->comm, current->pid);
				}
				

				// 2. Check if packet destination is DDS multicast address
				else if(ntohs(daddr) == 61439)
				{
					allow = true;
					// printk(KERN_INFO "apparmor_socket_sendmsg (%s): DDS Multicast allowed %pi4, current_pid = %d\n", current->comm, &daddr, current->pid);
				}

				// 3. Check if destination address is multicast address
				else if(((daddr & 0x000000FF) >= 224) && ((daddr & 0x000000FF) <= 239))
				{
					allow = true;
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

                    allow = apparmor_domain_declassify(curr_profile, daddr);
					if(allow)
					{
						printk (KERN_INFO "[GRAPH_GEN] Process %s, network, %pi4\n", curr_profile->base.hname, &daddr);
					}
					// printk(KERN_INFO "apparmor_socket_sendmsg (%s): Domain declassification for message from process %s(pid = %d) to address %pi4, flow is %d\n", current->comm, current->comm, current->pid, &daddr, allow);
				}				
				
			}//end of if(sk->sk_family == AF_INET)
		
		}//end if (curr_domain != NULL)
		else
		{
			allow = true;
		}
		
		sendmsg_out:
		aa_put_profile(curr_sock_profile);
		
	}
	else
	{
		allow = true;
	}
	

	aa_put_profile(curr_profile);
	if (!allow)
	{
		printk (KERN_INFO "sendmsg (%s): return is -13\n", current->comm);
		return -EACCES;
	}
	
    return 0;
}



/**
 * apparmor_socket_recvmsg - check perms before receiving a message
 */
static int apparmor_socket_recvmsg(struct socket *sock,
				   struct msghdr *msg, int size, int flags)
{
	struct aa_profile *curr_profile;
    struct aa_profile *curr_sock_profile;
	struct aa_profile *sender_profile;
	struct task_struct *sender;
	bool allow = true;		
	__u32 sender_pid;
	struct aa_sk_ctx *ctx = SK_CTX(sock->sk);
	char *curr_domain = NULL;

	curr_profile = aa_get_task_profile(current);

	if(curr_profile != NULL && !unconfined(curr_profile) && ctx != NULL && ctx->profile != NULL)
	{
		curr_sock_profile = aa_get_profile(ctx->profile);

		//get the domain from current process profile and not from socket's profile, coz socket's can be passed
		if(curr_profile->current_domain != NULL && curr_profile->current_domain->domain != NULL)
        {
            curr_domain = curr_profile->current_domain->domain;
        }

		curr_sock_profile->recv_pid = current->pid;

		if (curr_domain != NULL && curr_sock_profile->pid != 0)
		{
			// printk (KERN_INFO "apparmor_socket_recvmsg (%s): current_pid %d, sk_family=%d, sock->type=%d\n", current->comm, current->pid, sock->sk->sk_family, sock->type);
			
			if(sock->sk->sk_family == AF_INET)
			{
				sender_pid = curr_sock_profile->pid;
				// sender = pid_task(find_vpid(sender_pid), PIDTYPE_PID);
				sender = get_pid_task(find_get_pid(sender_pid), PIDTYPE_PID);
				if (sender == NULL)
				{
					sender_profile = apparmor_tsk_container_get(sender_pid);
				}
				else
				{
					sender_profile = aa_get_task_profile(sender);
				}

				if (sender_profile != NULL)
				{
					if (sender_pid != current->pid )
					{
						//add sender & receiver profile to cache
						apparmor_tsk_container_add(curr_profile, current->pid);

                        allow = apparmor_check_for_flow(sender_profile, curr_domain);

						if (allow)
							printk (KERN_INFO "[GRAPH_GEN] Process %s, socket_ipc, %s\n", sender_profile->base.hname, curr_profile->base.hname);
						
						// printk (KERN_INFO "apparmor_socket_recvmsg (%s): Match is %d for flow from %s(pid = %d) to %s(pid = %d)\n", current->comm, allow, sender_label->hname, sender_pid, current->comm, current->pid);
					}
					
					aa_put_profile(sender_profile);	
				}
				else
				{
					// printk (KERN_INFO "apparmor_socket_recvmsg (%s): else statement for (if (sender_pid != current->pid && sender_label != NULL)) sender pid: %d, current pid: %d\n", current->comm, sender_pid, current->pid);
				}
				
				
				
				
			}//end of if(sock->sk->sk_family == AF_INET )
			else if(sock->sk->sk_family == AF_UNIX)
			{
				// printk (KERN_INFO "apparmor_socket_recvmsg: UNIX DOMAIN SOCKET \n");
				// printk (KERN_INFO "apparmor_socket_recvmsg: address pair = %lld, port_pair = %d \n", sock->sk->sk_addrpair, sock->sk->sk_portpair);
				// printk (KERN_INFO "apparmor_socket_recvmsg: desti addr = %d, desti port = %d,  sk_rcv_saddr = %d, sk_num = %d \n", sock->sk->sk_daddr, 														sock->sk->sk_dport, sock->sk->sk_rcv_saddr, sock->sk->sk_num);
			}
		} // end for if (curr_domain != NULL)	
		
		aa_put_profile(curr_sock_profile);
	}

	aa_put_profile(curr_profile);
	if (!allow)
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
		printk (KERN_INFO "recvmsg (%s): return is -13, status of drop_flag = %d\n", current->comm, drop_flag);
		return -EACCES;
	}
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
	struct aa_profile *profile;
    char *curr_domain = NULL;
    const struct tcphdr *tcpheader;
    bool allow = true;

	if (ctx != NULL && ctx->profile != NULL)
	{
		profile = aa_get_profile(ctx->profile);

		if(profile->current_domain != NULL && profile->current_domain->domain != NULL)
        {
            curr_domain = profile->current_domain->domain;
        }

		if(curr_domain != NULL && (sk->sk_type == SOCK_STREAM))
		{
			tcpheader = tcp_hdr(skb);
			if (skb->secmark != profile->pid && skb->secmark != 0)
			{
				profile->pid = skb->secmark;
				allow = apparmor_socket_label_compare(profile->pid, profile->recv_pid);
				printk (KERN_INFO "socket_sock_rcv_skb: TCP socket label_name: %s, profile->pid %d, profile->recv_pid %d, skb->pid %d, skb->data_len %d, syn = %d, ack = %d, fin = %d, allow = %d\n", profile->base.hname, profile->pid, profile->recv_pid, skb->secmark, skb->data_len, tcpheader->syn, tcpheader->ack, tcpheader->fin, allow);
			}
		}

		// if (curr_domain != NULL && (sk->sk_type == SOCK_DGRAM || 
			// (sk->sk_type == SOCK_STREAM && tcpheader->fin != 1 && tcpheader->syn != 1 && tcpheader->ack != 1  )))

		else if (curr_domain != NULL && (sk->sk_type == SOCK_DGRAM))
		{
			// printk (KERN_INFO "apparmor_socket_sock_rcv_skb: UDP socket label_name: %s, profile->pid %d, profile->recv_pid %d, skb->pid %d, skb->data_len %d\n", profile->hname, profile->pid, profile->recv_pid, skb->secmark, skb->data_len);
			// printk (KERN_INFO "skb len %d skb data_len %d\n", skb->len, skb->data_len);
			allow = apparmor_socket_label_compare(profile->pid, profile->recv_pid);
		}
		
		aa_put_profile(ctx->profile);	

        if (!allow)
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
			printk(KERN_INFO "socket_sock_rcv_skb: returning -EACCES\n");
            return -EACCES;
        }	
	}
	return 0;
}

static int apparmor_inet_conn_request(struct sock *sk, struct sk_buff *skb,
				      struct request_sock *req)
{
	struct aa_sk_ctx *ctx = SK_CTX(sk);
	struct aa_profile *profile = aa_get_profile(ctx->profile);
	printk(KERN_INFO "inet_conn_request: sock_profile: %s\n", profile->base.hname);
	aa_put_profile(profile);
	return 0;
}




static struct security_hook_list apparmor_hooks[] = {
	LSM_HOOK_INIT(ptrace_access_check, apparmor_ptrace_access_check),
	LSM_HOOK_INIT(ptrace_traceme, apparmor_ptrace_traceme),
	LSM_HOOK_INIT(capget, apparmor_capget),
	LSM_HOOK_INIT(capable, apparmor_capable),

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

	LSM_HOOK_INIT(file_open, apparmor_file_open),
	LSM_HOOK_INIT(file_permission, apparmor_file_permission),
	LSM_HOOK_INIT(file_alloc_security, apparmor_file_alloc_security),
	LSM_HOOK_INIT(file_free_security, apparmor_file_free_security),
	LSM_HOOK_INIT(mmap_file, apparmor_mmap_file),
	LSM_HOOK_INIT(file_mprotect, apparmor_file_mprotect),
	LSM_HOOK_INIT(file_lock, apparmor_file_lock),

	LSM_HOOK_INIT(getprocattr, apparmor_getprocattr),
	LSM_HOOK_INIT(setprocattr, apparmor_setprocattr),

	LSM_HOOK_INIT(cred_alloc_blank, apparmor_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free, apparmor_cred_free),
	LSM_HOOK_INIT(cred_prepare, apparmor_cred_prepare),
	LSM_HOOK_INIT(cred_transfer, apparmor_cred_transfer),

	LSM_HOOK_INIT(bprm_set_creds, apparmor_bprm_set_creds),
	LSM_HOOK_INIT(bprm_committing_creds, apparmor_bprm_committing_creds),
	LSM_HOOK_INIT(bprm_committed_creds, apparmor_bprm_committed_creds),
	LSM_HOOK_INIT(bprm_secureexec, apparmor_bprm_secureexec),

	LSM_HOOK_INIT(task_setrlimit, apparmor_task_setrlimit),

	LSM_HOOK_INIT(sk_alloc_security, apparmor_sk_alloc_security),
	LSM_HOOK_INIT(sk_free_security, apparmor_sk_free_security),
	LSM_HOOK_INIT(sk_clone_security, apparmor_sk_clone_security),	
	LSM_HOOK_INIT(socket_post_create, apparmor_socket_post_create),
	LSM_HOOK_INIT(socket_sendmsg, apparmor_socket_sendmsg),
	LSM_HOOK_INIT(socket_recvmsg, apparmor_socket_recvmsg),
	LSM_HOOK_INIT(inet_conn_request, apparmor_inet_conn_request),
	#ifdef CONFIG_NETWORK_SECMARK
	LSM_HOOK_INIT(socket_sock_rcv_skb, apparmor_socket_sock_rcv_skb),
	#endif
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
bool aa_g_debug;
module_param_named(debug, aa_g_debug, aabool, S_IRUSR | S_IWUSR);

/* Audit mode */
enum audit_mode aa_g_audit;
module_param_call(audit, param_set_audit, param_get_audit,
		  &aa_g_audit, S_IRUSR | S_IWUSR);

/* Determines if audit header is included in audited messages.  This
 * provides more context if the audit daemon is not running
 */
bool aa_g_audit_header = 1;
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
 */
bool aa_g_paranoid_load = 1;
module_param_named(paranoid_load, aa_g_paranoid_load, aabool,
		   S_IRUSR | S_IWUSR);

/* Boot time disable flag */
static bool apparmor_enabled = CONFIG_SECURITY_APPARMOR_BOOTPARAM_VALUE;
module_param_named(enabled, apparmor_enabled, bool, S_IRUGO);

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
	if (!policy_admin_capable())
		return -EPERM;
	return param_set_bool(val, kp);
}

static int param_get_aalockpolicy(char *buffer, const struct kernel_param *kp)
{
	if (!policy_view_capable())
		return -EPERM;
	return param_get_bool(buffer, kp);
}

static int param_set_aabool(const char *val, const struct kernel_param *kp)
{
	if (!policy_admin_capable())
		return -EPERM;
	return param_set_bool(val, kp);
}

static int param_get_aabool(char *buffer, const struct kernel_param *kp)
{
	if (!policy_view_capable())
		return -EPERM;
	return param_get_bool(buffer, kp);
}

static int param_set_aauint(const char *val, const struct kernel_param *kp)
{
	if (!policy_admin_capable())
		return -EPERM;
	return param_set_uint(val, kp);
}

static int param_get_aauint(char *buffer, const struct kernel_param *kp)
{
	if (!policy_view_capable())
		return -EPERM;
	return param_get_uint(buffer, kp);
}

static int param_get_audit(char *buffer, const struct kernel_param *kp)
{
	if (!policy_view_capable())
		return -EPERM;

	if (!apparmor_enabled)
		return -EINVAL;

	return sprintf(buffer, "%s", audit_mode_names[aa_g_audit]);
}

static int param_set_audit(const char *val, const struct kernel_param *kp)
{
	int i;
	if (!policy_admin_capable())
		return -EPERM;

	if (!apparmor_enabled)
		return -EINVAL;

	if (!val)
		return -EINVAL;

	for (i = 0; i < AUDIT_MAX_INDEX; i++) {
		if (strcmp(val, audit_mode_names[i]) == 0) {
			aa_g_audit = i;
			return 0;
		}
	}

	return -EINVAL;
}

static int param_get_mode(char *buffer, const struct kernel_param *kp)
{
	if (!policy_admin_capable())
		return -EPERM;

	if (!apparmor_enabled)
		return -EINVAL;

	return sprintf(buffer, "%s", aa_profile_mode_names[aa_g_profile_mode]);
}

static int param_set_mode(const char *val, const struct kernel_param *kp)
{
	int i;
	if (!policy_admin_capable())
		return -EPERM;

	if (!apparmor_enabled)
		return -EINVAL;

	if (!val)
		return -EINVAL;

	for (i = 0; i < APPARMOR_MODE_NAMES_MAX_INDEX; i++) {
		if (strcmp(val, aa_profile_mode_names[i]) == 0) {
			aa_g_profile_mode = i;
			return 0;
		}
	}

	return -EINVAL;
}

/*
 * AppArmor init functions
 */

/**
 * set_init_cxt - set a task context and profile on the first task.
 *
 * TODO: allow setting an alternate profile than unconfined
 */
static int __init set_init_cxt(void)
{
	struct cred *cred = (struct cred *)current->real_cred;
	struct aa_task_cxt *cxt;

	cxt = aa_alloc_task_context(GFP_KERNEL);
	if (!cxt)
		return -ENOMEM;

	cxt->profile = aa_get_profile(root_ns->unconfined);
	cred_cxt(cred) = cxt;

	return 0;
}

static int __init apparmor_init(void)
{
	int error;

	if (!apparmor_enabled || !security_module_enable("apparmor")) {
		aa_info_message("AppArmor disabled by boot time parameter");
		apparmor_enabled = 0;
		return 0;
	}

	error = aa_alloc_root_ns();
	if (error) {
		AA_ERROR("Unable to allocate default profile namespace\n");
		goto alloc_out;
	}

	error = set_init_cxt();
	if (error) {
		AA_ERROR("Failed to set context on init task\n");
		aa_free_root_ns();
		goto alloc_out;
	}
	security_add_hooks(apparmor_hooks, ARRAY_SIZE(apparmor_hooks));

	/* Report that AppArmor successfully initialized */
	apparmor_initialized = 1;
	if (aa_g_profile_mode == APPARMOR_COMPLAIN)
		aa_info_message("AppArmor initialized: complain mode enabled");
	else if (aa_g_profile_mode == APPARMOR_KILL)
		aa_info_message("AppArmor initialized: kill mode enabled");
	else
		aa_info_message("AppArmor initialized");

	return error;

alloc_out:
	aa_destroy_aafs();

	apparmor_enabled = 0;
	return error;
}

security_initcall(apparmor_init);
