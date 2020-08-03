/*
 *   Copyright (c) 2012
 *   Canonical, Ltd. (All rights reserved)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 */
#ifndef __AA_PROFILE_H
#define __AA_PROFILE_H

#include <set>
#include <string>
#include <iostream>

#include "parser.h"
#include "rule.h"
#include "libapparmor_re/aare_rules.h"
#include "network.h"

class Profile;

class block {
public:

};


struct deref_profileptr_lt {
	bool operator()(Profile * const &lhs, Profile * const &rhs) const;
};

class ProfileList {
public:
	set<Profile *, deref_profileptr_lt> list;

	typedef set<Profile *, deref_profileptr_lt>::iterator iterator;
	iterator begin() { return list.begin(); }
	iterator end() { return list.end(); }

	ProfileList() { };
	virtual ~ProfileList() { clear(); }
	virtual bool empty(void) { return list.empty(); }
	virtual pair<ProfileList::iterator,bool> insert(Profile *);
	virtual void erase(ProfileList::iterator pos);
	void clear(void);
	void dump(void);
	void dump_profile_names(bool children);
};



class flagvals {
public:
	int hat;
	int complain;
	int audit;
	int path;

	void dump(void)
	{
		printf("Profile Mode:\t");

		if (complain)
			printf("Complain");
		else
			printf("Enforce");

		if (audit)
			printf(", Audit");

		if (hat)
			printf(", Hat");

		printf("\n");
	}
};

struct capabilities {
	uint64_t allow;
	uint64_t audit;
	uint64_t deny;
	uint64_t quiet;

	capabilities(void) { allow = audit = deny = quiet = 0; }

	void dump()
		{
			if (allow != 0ull)
				__debug_capabilities(allow, "Capabilities");
			if (audit != 0ull)
				__debug_capabilities(audit, "Audit Caps");
			if (deny != 0ull)
				__debug_capabilities(deny, "Deny Caps");
			if (quiet != 0ull)
				__debug_capabilities(quiet, "Quiet Caps");
		};
};

struct dfa_stuff {
	aare_rules *rules;
	void *dfa;
	size_t size;

	dfa_stuff(void): rules(NULL), dfa(NULL), size(0) { }
};

struct ListOfDomains
{
	char *domain;
	struct ListOfDomains *next;
};


struct DomainMetaData
{
	char *domain;
	int allow_cnt;
	int deny_cnt;
	int ip_allow_cnt;
};
struct Is_Trusted_t
{
	char *flag;
};

class Profile {
public:
	//profile_base
	char *ns;
	//profile_base
	char *name;

	//sets inside profile_base:
	char *attachment;
	struct alt_name *altnames;

	//inside parser_regex->process_profile_name_xmatch
	void *xmatch;
	size_t xmatch_size;
	int xmatch_len;

	/* char *sub_name; */			/* subdomain name or NULL */
	/* int default_deny; */			/* TRUE or FALSE */
	//sets inside local_profile:
	int local;
	int local_mode;				/* true if local, not hat */
	int local_audit;

	//sets inside hats: | local_profile:
	Profile *parent;

	//profile_base, profile, hat
	flagvals flags;

	//capability
	struct capabilities caps;

	//network_rule
	struct network net;

	//sets inside last rules:
	struct aa_rlimits rlimits;

	char *exec_table[AA_EXEC_COUNT];

	//rule, change_profile
	struct cod_entry *entries;
	
	//network_rule, mnt_rule, dbus_rule, signal_rule, ptrace_rule, unix_rule
	RuleList rule_ents;

	ProfileList hat_table;

	//inside parser_regex -> process_profile_regex
	//is filled inside process_profile_regex
	struct dfa_stuff dfa;
	//inside parser_regex -> process_profile_policydb
	struct dfa_stuff policy;
	
	struct DomainMetaData *current_domain;
	struct ListOfDomains *allow_net_domains;
	struct ListOfDomains *deny_net_domains;
	struct ListOfIPAddrs *allowed_ip_addrs;
	struct Is_Trusted_t *is_trusted_var;

	Profile(void)
	{
		ns = name = attachment = NULL;
		altnames = NULL;
		xmatch = NULL;
		xmatch_size = 0;
		xmatch_len = 0;

		local = local_mode = local_audit = 0;

		parent = NULL;

		flags = { 0, 0, 0, 0};
		rlimits = {0, {}};

		std::fill(exec_table, exec_table + AA_EXEC_COUNT, (char *)NULL);

		entries = NULL;
		current_domain = NULL;
		allow_net_domains = NULL;
		deny_net_domains = NULL;
	};

	virtual ~Profile();

	bool operator<(Profile const &rhs)const
	{
		if (ns) {
			if (rhs.ns) {
				int res = strcmp(ns, rhs.ns);
				if (res != 0)
					return res < 0;
			} else
				return false;
		} else if (rhs.ns)
			return true;
		return strcmp(name, rhs.name) < 0;
	}

	void dump(void)
	{
		if (ns)
			printf("Ns:\t\t%s\n", ns);

		if (name)
			printf("Name:\t\t%s\n", name);
		else
			printf("Name:\t\t<NULL>\n");

		if (local) {
			if (parent)
				printf("Local To:\t%s\n", parent->name);
			else
				printf("Local To:\t<NULL>\n");
		}
		printf ("flags------------------------------\n");
		flags.dump();
		printf ("caps------------------------------\n");
		caps.dump();
		printf ("net------------------------------\n");
		net.dump();
		printf ("cod_entries------------------------------\n");
		if (entries)
			debug_cod_entries(entries);
		printf ("rulelist------------------------------\n");
		for (RuleList::iterator i = rule_ents.begin(); i != rule_ents.end(); i++) {
			(*i)->dump(cout);
		}
		
		printf("\n");
		printf ("hat_table------------------------------\n");
		hat_table.dump();
		printf ("exec_table------------------------------\n");
		for(int i = 0; i < AA_EXEC_COUNT; i++)
		{
			printf ("%s\n", exec_table[i]);
		}
		
	}

	bool alloc_net_table();

	std::string hname(void)
	{
		if (!parent)
			return name;

		return parent->hname() + "//" + name;
	}

	/* assumes ns is set as part of profile creation */
	std::string fqname(void)
	{
		if (parent)
			return parent->fqname() + "//" + name;
		else if (!ns)
			return hname();
		return ":" + std::string(ns) + "://" + hname();
	}

	std::string get_name(bool fqp)
	{
		if (fqp)
			return fqname();
		return hname();
	}

	void dump_name(bool fqp)
	{
		cout << get_name(fqp);;
	}
};


#endif /* __AA_PROFILE_H */
