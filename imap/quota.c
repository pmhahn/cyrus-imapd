/* quota.c -- program to report/reconstruct quotas
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * $Id: quota.c,v 1.72 2010/01/06 17:01:39 murch Exp $
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/poll.h>

#if HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#include "assert.h"
#include "bsearch.h"
#include "cyrusdb.h"
#include "global.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "mboxlist.h"
#include "mboxname.h"
#include "quota.h"
#include "convert_code.h"
#include "util.h"

extern int optind;
extern char *optarg;

/* current namespace */
static struct namespace quota_namespace;

/* config.c stuff */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;

struct quotaentry {
    struct quota quota;
    char *allocname;
    int refcount;
    int deleted;
    quota_t newused;
};

/* forward declarations */
void usage(void);
void reportquota(void);
static int buildquotalist(char *domain, char **roots, int nroots);
static int fixquotas(char *domain, char **roots, int nroots);
static int fixquota_dopass(char *domain, char **roots, int nroots,
			   foreach_cb *pass);
static int fixquota_pass1(void *rock, const char *name, int namelen,
			  const char *val, int vallen);
static int fixquota_pass2(void *rock, const char *name, int namelen,
			  const char *val, int vallen);
static int fixquota_fixroot(struct mailbox *mailbox, const char *root);
static int fixquota_finish(int thisquota);
static int (*compar)(const char *s1, const char *s2);

#define QUOTAGROW 300

struct quotaentry *quota;
int quota_num = 0, quota_alloc = 0;

int firstquota = 0;
int redofix = 0;
int test_sync_mode = 0;

int main(int argc,char **argv)
{
    int opt;
    int i;
    int fflag = 0;
    int r, code = 0;
    int do_report = 1;
    char *alt_config = NULL, *domain = NULL;

    if ((geteuid()) == 0 && (become_cyrus() != 0)) {
	fatal("must run as the Cyrus user", EC_USAGE);
    }

    while ((opt = getopt(argc, argv, "C:d:fqZ")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 'q':
	    do_report = 0;
	    break;

	case 'd':
	    domain = optarg;
	    break;

	case 'f':
	    fflag = 1;
	    break;

	/* deliberately undocumented option for testing */
	case 'Z':
	    test_sync_mode = 1;
	    break;

	default:
	    usage();
	}
    }

    /* always report if not fixing, otherwise we do nothing */
    if (!fflag)
	do_report = 1;

    cyrus_init(alt_config, "quota", 0);

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&quota_namespace, 1)) != 0) {
	syslog(LOG_ERR, "%s", error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    if (config_getswitch(IMAPOPT_IMPROVED_MBOXLIST_SORT))
	compar = bsearch_compare;
    else
	compar = strcmp;

    /*
     * Lock mailbox list to prevent mailbox creation/deletion
     * during work
     */
    mboxlist_init(0);
    mboxlist_open(NULL);

    quotadb_init(0);
    quotadb_open(NULL);

    if (fflag)
	r = fixquota_dopass(domain, argv+optind, argc-optind, fixquota_pass1);

    if (!r)
	r = buildquotalist(domain, argv+optind, argc-optind);

    if (!r && fflag)
	r = fixquotas(domain, argv+optind, argc-optind);

    quotadb_close();
    quotadb_done();

    mboxlist_close();
    mboxlist_done();

    if (r) code = convert_code(r);
    else if (do_report) reportquota();

    /* just for neatness */
    for (i = 0; i < quota_num; i++)
	free(quota[i].allocname);
    free(quota);

    cyrus_done();

    return code;
}

void usage(void)
{
    fprintf(stderr,
	    "usage: quota [-C <alt_config>] [-d <domain>] [-f] [-q] [prefix]...\n");
    exit(EC_USAGE);
}

void errmsg(const char *fmt, const char *arg, int err)
{
    char buf[1024];
    size_t len;

    len = snprintf(buf, sizeof(buf), fmt, arg);
    if (len < sizeof(buf))
	len += snprintf(buf+len, sizeof(buf)-len, ": %s", error_message(err));
    if ((err == IMAP_IOERROR) && (len < sizeof(buf)))
	len += snprintf(buf+len, sizeof(buf)-len, ": %s", strerror(errno));

    syslog(LOG_ERR, "%s", buf);
    fprintf(stderr, "%s\n", buf);
}

static void test_sync_wait(const char *mboxname)
{
    char *filename;
    struct stat sb;
    clock_t start;
    int status = 0;
    int r;
#define TIMEOUT	    (30 * CLOCKS_PER_SEC)

    if (!test_sync_mode)
	return;
    /* aha, we're in test synchronisation mode */

    syslog(LOG_ERR, "quota -Z waiting for signal to do %s", mboxname);

    filename = strconcat(config_dir, "/quota-sync/", mboxname, (char *)NULL);
    start = sclock();

    while ((r = stat(filename, &sb)) < 0 && errno == ENOENT) {
	if (sclock() - start > TIMEOUT) {
	    status = 2;
	    break;
	}
	status = 1;
	poll(NULL, 0, 20);  /* try again in 20 millisec */
    }

    switch (status)
    {
    case 0:
	syslog(LOG_ERR, "quota -Z did not wait");
	break;
    case 1:
	syslog(LOG_ERR, "quota -Z waited %2.3f sec",
			 (sclock() - start) / (double) CLOCKS_PER_SEC);
	break;
    case 2:
	syslog(LOG_ERR, "quota -Z timed out");
	break;
    }

    free(filename);
#undef TIMEOUT
}

static void test_sync_done(const char *mboxname)
{
    char *filename;

    if (!test_sync_mode)
	return;
    /* aha, we're in test synchronisation mode */

    syslog(LOG_ERR, "quota -Z done with %s", mboxname);

    filename = strconcat(config_dir, "/quota-sync/", mboxname, (char *)NULL);
    unlink(filename);
    free(filename);
}


/*
 * A quotaroot was found, add it to our list
 */
static int fixquota_addroot(struct quota *q,
			    void *rock __attribute__((unused)))
{
    if (quota_num == quota_alloc) {
	/* Create new qr list entry */
	quota_alloc += QUOTAGROW;
	quota = (struct quotaentry *)
	    xrealloc((char *)quota, quota_alloc * sizeof(struct quotaentry));
	memset(&quota[quota_num], 0, QUOTAGROW * sizeof(struct quotaentry));
    }

    /* copy this quota */
    quota[quota_num].allocname   = xstrdup(q->root);
    memcpy(&quota[quota_num].quota, q, sizeof(*q));
    quota[quota_num].quota.root  = quota[quota_num].allocname;
    quota_num++;

    return 0;
}

/*
 * Build the list of quota roots in 'quota'
 */
int buildquotalist(char *domain, char **roots, int nroots)
{
    int i, r;
    char buf[MAX_MAILBOX_BUFFER], *tail;
    size_t domainlen = 0;
    struct txn *tid = NULL;

    buf[0] = '\0';
    tail = buf;
    if (domain) {
	domainlen = snprintf(buf, sizeof(buf), "%s!", domain);
	tail += domainlen;
    }

    /* basic case - everything (potentially limited by domain still) */
    if (!nroots) {
	r = quota_foreach(buf, fixquota_addroot, NULL, &tid);
	if (r) {
	    errmsg("failed building quota list for '%s'", buf, IMAP_IOERROR);
	}
    }

    /*
     * Walk through all given pattern(s) and add all the quota roots
     * with the matching prefixes.
     */
    for (i = 0; i < nroots; i++) {
	strlcpy(tail, roots[i], sizeof(buf) - domainlen);
	/* change the separator to internal namespace */
	mboxname_hiersep_tointernal(&quota_namespace, tail, 0);

	r = quota_foreach(buf, fixquota_addroot, NULL, &tid);
	if (r) {
	    errmsg("failed building quota list for '%s'", buf, IMAP_IOERROR);
	    break;
	}
    }

    /*
     * Mark the quotaroots in the db to non-invalid to indicate
     * that a scan is in progress.  Other processes doing quota
     * updates for mailboxes will now start to update usedBs[].
     */
    for (i = 0; i < quota_num; i++) {
	quota[i].quota.usedBs[QUOTA_STORAGE] = 0;
	r = quota_write(&quota[i].quota, &tid);
	if (r) {
	    errmsg("failed writing quota record for '%s'",
		   quota[i].quota.root, r);
	    break;
	}
    }

    if (r)
	quota_abort(&tid);
    else
	quota_commit(&tid);

    return r;
}

static int findroot(const char *name, int *thisquota)
{
    int i;

    *thisquota = -1;

    for (i = firstquota; i < quota_num; i++) {
	const char *root = quota[i].quota.root;

	/* have we already passed the name, then there can
	 * be no further matches */
	if (compar(root, name) > 0)
	    return 0;

	/* is the mailbox within this root? */
	if (mboxname_is_prefix(name, root)) {
	    /* fantastic, but don't return yet, we may find
	     * a more exact match */
	    quota[i].refcount++;
	    *thisquota = i;
	}
	else {
	    /* not a match, so we can finish everything up to here */
	    while (firstquota < i) {
		int r = fixquota_finish(firstquota);
		if (r) return r;
		firstquota++;
	    }
	}
    }

    return 0;
}

/*
 * Pass 1: reset the 'scanned' flag on each mailbox.
 */
static int fixquota_pass1(void *rock __attribute__((unused)),
			  const char *name, int namelen,
			  const char *val __attribute__((unused)),
			  int vallen __attribute__((unused)))
{
    int r = 0;
    struct mailbox *mailbox = NULL;
    char *mboxname = xstrndup(name, namelen);

    r = mailbox_open_iwl(mboxname, &mailbox);
    if (r) {
	errmsg("failed opening header for mailbox '%s'", name, r);
	goto done;
    }

    if ((mailbox->i.options & OPT_MAILBOX_QUOTA_SCANNED)) {
	mailbox_index_dirty(mailbox);
	mailbox->i.options &= ~OPT_MAILBOX_QUOTA_SCANNED;
    }

done:
    mailbox_close(&mailbox);
    free(mboxname);

    return r;
}

/*
 * Pass 2: account for mailbox 'name' when fixing the quota roots
 *         and set the 'scanned' flag so that mailbox updates racing
 *         with us will start updating the usedBs[].
 */
static int fixquota_pass2(void *rock __attribute__((unused)),
			  const char *name, int namelen,
			  const char *val __attribute__((unused)),
			  int vallen __attribute__((unused)))
{
    int r = 0;
    struct mailbox *mailbox = NULL;
    int thisquota = -1;
    char *mboxname = xstrndup(name, namelen);

    test_sync_wait(mboxname);

    r = findroot(mboxname, &thisquota);
    if (r) {
	errmsg("failed finding quotaroot for mailbox '%s'", name, r);
	goto done;
    }

    r = mailbox_open_iwl(mboxname, &mailbox);
    if (r) {
	errmsg("failed opening header for mailbox '%s'", name, r);
	goto done;
    }

    if (thisquota == -1) {
	/* no matching quotaroot exists, remove from
	 * mailbox if present */
	if (mailbox->quotaroot) {
	    r = fixquota_fixroot(mailbox, (char *)0);
	}
    }
    else {
	/* matching quotaroot exists, ensure mailbox has the
	 * correct root */
	if (!mailbox->quotaroot ||
	    strcmp(mailbox->quotaroot, quota[thisquota].quota.root) != 0) {
	    r = fixquota_fixroot(mailbox, quota[thisquota].quota.root);
	}

	/* and track the total usage inside this root */
	if (!r) {
	    quota[thisquota].newused += mailbox->i.quota_mailbox_used;
	    /* Set the 'scanned' flag in the mailbox */
	    mailbox_index_dirty(mailbox);
	    mailbox->i.options |= OPT_MAILBOX_QUOTA_SCANNED;
	}
    }

done:
    mailbox_close(&mailbox);
    test_sync_done(mboxname);
    free(mboxname);

    return r;
}

int fixquota_fixroot(struct mailbox *mailbox,
		     const char *root)
{
    int r;

    printf("%s: quota root %s --> %s\n", mailbox->name,
	   mailbox->quotaroot ? mailbox->quotaroot : "(none)",
	   root ? root : "(none)");

    r = mailbox_set_quotaroot(mailbox, root);
    if (r) errmsg("failed writing header for mailbox '%s'", mailbox->name, r);

    return r;
}

/*
 * Pass 3: finish fixing up a quota root
 */
int fixquota_finish(int thisquota)
{
    int r = 0;
    struct txn *tid = NULL;

    if (!quota[thisquota].refcount) {
	printf("%s: removed\n", quota[thisquota].quota.root);
	r = quota_deleteroot(quota[thisquota].quota.root);
	if (r) {
	    errmsg("failed deleting quotaroot '%s'",
		   quota[thisquota].quota.root, r);
	}
	return r;
    }

    /* re-read the quota with the record locked */
    r = quota_read(&quota[thisquota].quota, &tid, 1);
    if (r) {
	errmsg("failed reading quotaroot '%s'",
	       quota[thisquota].quota.root, r);
	return r;
    }

    if (quota[thisquota].quota.usedBs[QUOTA_STORAGE] != QUOTA_INVALID) {
	/* adjust the newused figure for accumulated mailbox
	 * updates which lost the race against the scan */
	quota[thisquota].newused += quota[thisquota].quota.usedBs[QUOTA_STORAGE];
	/* reset usedBs to record that the scan is complete */
	quota[thisquota].quota.usedBs[QUOTA_STORAGE] = QUOTA_INVALID;
    }

    /* is it still different? */
    if (quota[thisquota].quota.useds[QUOTA_STORAGE] != quota[thisquota].newused) {
	printf("%s: usage was " QUOTA_T_FMT ", now " QUOTA_T_FMT "\n",
	       quota[thisquota].quota.root,
	       quota[thisquota].quota.useds[QUOTA_STORAGE], quota[thisquota].newused);
	quota[thisquota].quota.useds[QUOTA_STORAGE] = quota[thisquota].newused;
    }

    /* always write out the record, we should have just reset usedBs */
    r = quota_write(&quota[thisquota].quota, &tid);
    if (r) {
	errmsg("failed writing quotaroot '%s'",
	       quota[thisquota].quota.root, r);
	quota_abort(&tid);
	return r;
    }

    quota_commit(&tid);

    return 0;
}

/*
 * Run a pass over all the quota roots
 */
int fixquota_dopass(char *domain, char **roots, int nroots,
		    foreach_cb *pass)
{
    int i, r;
    char buf[MAX_MAILBOX_BUFFER], *tail;
    size_t domainlen = 0;

    buf[0] = '\0';
    tail = buf;
    if (domain) {
	domainlen = snprintf(buf, sizeof(buf), "%s!", domain);
	tail += domainlen;
    }

    /* basic case - everything (potentially limited by domain still) */
    if (!nroots) {
	r = mboxlist_allmbox(buf, pass, NULL);
	if (r) {
	    errmsg("processing mbox list for '%s'", buf, IMAP_IOERROR);
	}
    }

    /*
     * Walk through all given pattern(s) and add all the quota roots
     * with the matching prefixes.
     */
    for (i = 0; i < nroots; i++) {
	strlcpy(tail, roots[i], sizeof(buf) - domainlen);
	/* change the separator to internal namespace */
	mboxname_hiersep_tointernal(&quota_namespace, tail, 0);

	r = mboxlist_allmbox(buf, pass, NULL);
	if (r) {
	    errmsg("processing mbox list for '%s'", buf, IMAP_IOERROR);
	    break;
	}
    }

    return r;
}

/*
 * Fix all the quota roots
 */
int fixquotas(char *domain, char **roots, int nroots)
{
    int r;

    r = fixquota_dopass(domain, roots, nroots, fixquota_pass2);

    while (!r && firstquota < quota_num) {
	r = fixquota_finish(firstquota);
	firstquota++;
    }

    return r;
}

/*
 * Print out the quota report
 */
void reportquota(void)
{
    int i;
    char buf[MAX_MAILBOX_PATH+1];

    printf("   Quota   %% Used     Used Root\n");

    for (i = 0; i < quota_num; i++) {
	if (quota[i].deleted) continue;
	if (quota[i].quota.limits[QUOTA_STORAGE] > 0) {
	    printf(" %7d %8lld" ,
		    quota[i].quota.limits[QUOTA_STORAGE],
		   ((quota[i].quota.useds[QUOTA_STORAGE] / quota_units[QUOTA_STORAGE])
		   * 100) / quota[i].quota.limits[QUOTA_STORAGE]);
	}
	else if (quota[i].quota.limits[QUOTA_STORAGE] == 0) {
	    printf("       0        ");
	}
	else {
	    printf("                ");
	}
	/* Convert internal name to external */
	(*quota_namespace.mboxname_toexternal)(&quota_namespace,
					       quota[i].quota.root,
					       "cyrus", buf);
	printf(" %8lld %s\n",
	       quota[i].quota.useds[QUOTA_STORAGE] / quota_units[QUOTA_STORAGE], buf);
    }
}
