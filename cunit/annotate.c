#if HAVE_CONFIG_H
#include <config.h>
#endif
#include "cunit/cunit.h"
#include "xmalloc.h"
#include "retry.h"
#include "global.h"
#include "libcyr_cfg.h"
#include "annotate.h"
#include "mboxlist.h"

#define DBDIR		"test-dbdir"
#define MBOXNAME1_INT   "user.smurf"
#define MBOXNAME1_EXT   "INBOX"
#define MBOXNAME2_INT   "user.smurfette"
#define MBOXNAME2_EXT   "user.smurfette"
#define PARTITION	"default"
#define COMMENT		"/comment"
#define SHARED		"value.shared"
#define VALUE0		"Hello World"
#define ACL		"anyone\tlrswipkxtecdan\t"

static struct namespace namespace;
static int isadmin;
static const char *userid;
static struct auth_state *auth_state;

static void config_read_string(const char *s)
{
    char *fname = xstrdup("/tmp/cyrus-cunit-configXXXXXX");
    int fd = mkstemp(fname);
    retry_write(fd, s, strlen(s));
    config_reset();
    config_read(fname);
    unlink(fname);
    free(fname);
    close(fd);
}

static void fetch_cb(const char *mboxname, uint32_t uid,
		     const char *entry, struct attvaluelist *avlist,
		     void *rock)
{
    strarray_t *results = (strarray_t *)rock;
    struct buf buf = BUF_INITIALIZER;

    buf_printf(&buf, "mboxname=\"%s\" uid=%u entry=\"%s\"",
	       mboxname, uid, entry);

    for ( ; avlist ; avlist = avlist->next) {
	buf_printf(&buf, " %s=", avlist->attrib);
	if (avlist->value.s)
	    buf_printf(&buf, "\"%s\"", buf_cstring(&avlist->value));
	else
	    buf_printf(&buf, "NIL");
    }

    strarray_appendm(results, buf_release(&buf));
}

static void test_getset_server_shared(void)
{
    int r;
    annotate_scope_t scope;
    strarray_t entries = STRARRAY_INITIALIZER;
    strarray_t attribs = STRARRAY_INITIALIZER;
    strarray_t results = STRARRAY_INITIALIZER;
    struct entryattlist *ealist = NULL;
    struct buf val = BUF_INITIALIZER;
    struct buf val2 = BUF_INITIALIZER;

    annotatemore_open();

    annotate_scope_init_server(&scope);

    strarray_append(&entries, COMMENT);
    strarray_append(&attribs, SHARED);

    /* check that there is no value initially */

    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"\" " \
	   "uid=0 " \
	   "entry=\"" COMMENT "\" " \
	   SHARED "=NIL"
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_lookup(/*mboxname*/"", COMMENT, /*userid*/"", &val);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NULL(val.s);

    r = annotatemore_begin();
    CU_ASSERT_EQUAL(r, 0);

    /* set a value */

    buf_appendcstr(&val, VALUE0);
    setentryatt(&ealist, COMMENT, SHARED, &val);
    isadmin = 1;	/* pretend to be admin */
    r = annotatemore_store(&scope, ealist,
		           &namespace, isadmin, userid, auth_state);
    isadmin = 0;
    CU_ASSERT_EQUAL(r, 0);

    /* check that we can fetch the value back in the same txn */
    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"\" " \
	   "uid=0 " \
	   "entry=\"" COMMENT "\" " \
	   SHARED "=\"" VALUE0 "\""
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_lookup(/*mboxname*/"", COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_STRING_EQUAL(val2.s, VALUE0);

    r = annotatemore_commit();
    CU_ASSERT_EQUAL(r, 0);

    /* check that we can fetch the value back in a new txn */
    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"\" " \
	   "uid=0 " \
	   "entry=\"" COMMENT "\" " \
	   SHARED "=\"" VALUE0 "\""
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_lookup(/*mboxname*/"", COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_STRING_EQUAL(val2.s, VALUE0);

    annotatemore_close();

    /* check that we can fetch the value back after close and re-open */

    annotatemore_open();

    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"\" " \
	   "uid=0 " \
	   "entry=\"" COMMENT "\" " \
	   SHARED "=\"" VALUE0 "\""
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_lookup(/*mboxname*/"", COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_STRING_EQUAL(val2.s, VALUE0);

    annotatemore_close();

    strarray_fini(&entries);
    strarray_fini(&attribs);
    strarray_fini(&results);
    buf_free(&val);
    buf_free(&val2);
    freeentryatts(ealist);
}


static void test_getset_server_mailbox(void)
{
    int r;
    annotate_scope_t scope;
    strarray_t entries = STRARRAY_INITIALIZER;
    strarray_t attribs = STRARRAY_INITIALIZER;
    strarray_t results = STRARRAY_INITIALIZER;
    struct entryattlist *ealist = NULL;
    struct buf val = BUF_INITIALIZER;
    struct buf val2 = BUF_INITIALIZER;

    annotatemore_open();

    annotate_scope_init_mailbox(&scope, MBOXNAME1_INT);

    strarray_append(&entries, COMMENT);
    strarray_append(&attribs, SHARED);

    /* check that there is no value initially */

    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"" MBOXNAME1_EXT "\" " \
	   "uid=0 " \
	   "entry=\"" COMMENT "\" " \
	   SHARED "=NIL"
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_lookup(MBOXNAME1_INT, COMMENT, /*userid*/"", &val);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NULL(val.s);

    r = annotatemore_begin();
    CU_ASSERT_EQUAL(r, 0);

    /* set a value */

    buf_appendcstr(&val, VALUE0);
    setentryatt(&ealist, COMMENT, SHARED, &val);
    r = annotatemore_store(&scope, ealist,
		           &namespace, isadmin, userid, auth_state);
    CU_ASSERT_EQUAL(r, 0);

    /* check that we can fetch the value back in the same txn */
    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"" MBOXNAME1_EXT "\" " \
	   "uid=0 " \
	   "entry=\"" COMMENT "\" " \
	   SHARED "=\"" VALUE0 "\""
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_lookup(MBOXNAME1_INT, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_STRING_EQUAL(val2.s, VALUE0);

    r = annotatemore_commit();
    CU_ASSERT_EQUAL(r, 0);

    /* check that we can fetch the value back in a new txn */
    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"" MBOXNAME1_EXT "\" " \
	   "uid=0 " \
	   "entry=\"" COMMENT "\" " \
	   SHARED "=\"" VALUE0 "\""
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_lookup(MBOXNAME1_INT, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_STRING_EQUAL(val2.s, VALUE0);

    annotatemore_close();

    /* check that we can fetch the value back after close and re-open */

    annotatemore_open();

    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"" MBOXNAME1_EXT "\" " \
	   "uid=0 " \
	   "entry=\"" COMMENT "\" " \
	   SHARED "=\"" VALUE0 "\""
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_lookup(MBOXNAME1_INT, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_STRING_EQUAL(val2.s, VALUE0);

    annotatemore_close();

    strarray_fini(&entries);
    strarray_fini(&attribs);
    strarray_fini(&results);
    buf_free(&val);
    buf_free(&val2);
    freeentryatts(ealist);
}

static int set_up(void)
{
    int r;
    struct mboxlist_entry mbentry;
    const char * const *d;
    static const char * const dirs[] = {
	DBDIR,
	DBDIR"/db",
	DBDIR"/conf",
	NULL
    };

    r = system("rm -rf " DBDIR);
    if (r)
	return r;

    for (d = dirs ; *d ; d++) {
	r = mkdir(*d, 0777);
	if (r < 0) {
	    int e = errno;
	    perror(*d);
	    return e;
	}
    }

    libcyrus_config_setstring(CYRUSOPT_CONFIG_DIR, DBDIR);
    config_read_string(
	"configdirectory: "DBDIR"/conf\n"
	"defaultpartition: "PARTITION"\n"
	"partition-"PARTITION": "DBDIR"/data\n"
    );

    cyrusdb_init();
    config_mboxlist_db = cyrusdb_fromname("skiplist");
    config_annotation_db = cyrusdb_fromname("skiplist");

    userid = "smurf";
    isadmin = 0;
    auth_state = auth_newstate(userid);
    mboxname_init_namespace(&namespace, isadmin);

    mboxlist_init(0);
    mboxlist_open(NULL);

    memset(&mbentry, 0, sizeof(mbentry));
    mbentry.name = MBOXNAME1_INT;
    mbentry.mbtype = 0;
    mbentry.partition = PARTITION;
    mbentry.acl = ACL;
    r = mboxlist_update(&mbentry, /*localonly*/1);

    annotatemore_init(NULL, NULL);

    return 0;
}

static int tear_down(void)
{
    int r;

    mboxlist_close();
    mboxlist_done();

    annotatemore_done();

    auth_freestate(auth_state);

    cyrusdb_done();
    config_mboxlist_db = NULL;
    config_annotation_db = NULL;

    r = system("rm -rf " DBDIR);
    /* I'm ignoring you */

    return 0;
}
