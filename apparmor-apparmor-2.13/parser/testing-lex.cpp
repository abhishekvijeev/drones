#include <bits/stdc++.h>
#include "parser.h"
#include "profile.h"
#include "parser_include.h"
#include "parser_yacc.h"
#include "lib.h"
#include "policy_cache.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/apparmor.h>

#include <iostream>

/* #define DEBUG */

#include "parser.h"
#include "profile.h"
#include "mount.h"
#include "dbus.h"
#include "af_unix.h"
#include "parser_include.h"
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>

/* enable the following line to get voluminous debug info */
/* #define DEBUG */

#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <sys/apparmor.h>


#include "lib.h"
#include "features.h"
#include "parser.h"
#include "parser_version.h"
#include "parser_include.h"
#include "common_optarg.h"
#include "policy_cache.h"
#include "libapparmor_re/apparmor_re.h"

#include <linux/capability.h>

using namespace std;
int opt_force_complain = 0;
int binary_input = 0;
int dump_vars = 0;
int dump_expanded_vars = 0;
int show_cache = 0;
int skip_cache = 0;
int skip_read_cache = 0;
int write_cache = 0;
int cond_clear_cache = 1;		/* only applies if write is set */
int force_clear_cache = 0;		/* force clearing regargless of state */
int create_cache_dir = 0;		/* DEPRECATED in favor of write_cache */
int preprocess_only = 0;
int skip_mode_force = 0;
int abort_on_error = 0;			/* stop processing profiles if error */
int skip_bad_cache_rebuild = 0;
int mru_skip_cache = 1;
int debug_cache = 0;
void display_version(void)
{
}
struct timespec cache_tstamp, mru_policy_tstamp;




extern int yylex();
extern int yylineno;
extern char* yytext;


int main(void) 
{

	int ntoken, vtoken;

	ntoken = yylex();
	while(ntoken) {
		printf("%d is set to %s\n", ntoken, yytext);
		ntoken = yylex();
	}
	return 0;
}