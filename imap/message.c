/* message.c -- Message manipulation/parsing
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
 * $Id: message.c,v 1.118 2010/06/28 12:04:38 brong Exp $
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <assert.h>

#include "crc32.h"
#include "dlist.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "prot.h"
#include "map.h"
#include "mailbox.h"
#include "mkgmtime.h"
#include "message.h"
#include "message_guid.h"
#include "parseaddr.h"
#include "charset.h"
#include "stristr.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "strarray.h"
#include "global.h"
#include "retry.h"
#include "rfc822_header.h"
#include "times.h"

/* Message being parsed */
struct msg {
    const char *base;
    unsigned long len;
    unsigned long offset;
    int encode;
};

/* (draft standard) MIME tspecials */
#define TSPECIALS "()<>@,;:\\\"/[]?="

/* Default MIME Content-type */
#define DEFAULT_CONTENT_TYPE "TEXT/PLAIN; CHARSET=us-ascii"

static int message_parse_body(struct msg *msg,
				 struct body *body,
				 const char *defaultContentType,
				 strarray_t *boundaries);

static int message_parse_headers(struct msg *msg,
				    struct body *body,
				    const char *defaultContentType,
				    strarray_t *boundaries);
static void message_parse_address(const char *hdr, struct address **addrp);
static void message_parse_encoding(const char *hdr, char **hdrp);
static void message_parse_charset(const struct body *body,
				  int *encoding, int *charset);
static void message_parse_string(const char *hdr, char **hdrp);
static void message_parse_header(const char *hdr, struct ibuf *ibuf);
static void message_parse_type(const char *hdr, struct body *body);
/* static */ void message_parse_disposition(const char *hdr, struct body *body);
static void message_parse_params(const char *hdr, struct param **paramp);
static void message_fold_params(struct param **paramp);
static void message_parse_language(const char *hdr, struct param **paramp);
static void message_parse_rfc822space(const char **s);
static void message_parse_received_date(const char *hdr, char **hdrp);

static void message_parse_multipart(struct msg *msg,
				       struct body *body,
				       strarray_t *boundaries);
static void message_parse_content(struct msg *msg,
				     struct body *body,
				     strarray_t *boundaries);

static char *message_getline(char *s, unsigned n, struct msg *msg);
static int message_pendingboundary(const char *s, int slen, strarray_t *);

static void message_write_envelope(struct ibuf *ibuf, const struct body *body);
static void message_write_body(struct ibuf *ibuf, const struct body *body,
				  int newformat);
static void message_write_address(struct ibuf *ibuf,
				  const struct address *addrlist);
static void message_write_nstring(struct ibuf *ibuf, const char *s);
static void message_write_text(struct ibuf *ibuf, const char *s);
static void message_write_text_lcase(struct ibuf *ibuf, const char *s);
static void message_write_number(struct ibuf *ibuf, unsigned n);
static void message_write_section(struct ibuf *ibuf, const struct body *body);
static void message_write_charset(struct ibuf *ibuf, const struct body *body);
static void message_write_bit32(struct ibuf *ibuf, bit32 val);
static void message_write_searchaddr(struct ibuf *ibuf,
				     const struct address *addrlist);

static void message_ibuf_init(struct ibuf *ibuf);
static void message_ibuf_copy(struct ibuf *desc, const struct ibuf *src);
static int message_ibuf_ensure(struct ibuf *ibuf, unsigned len);
static void message_ibuf_pad(struct ibuf *ibuf);
static void message_ibuf_free(struct ibuf *ibuf);

/*
 * Convert a string to uppercase.  Returns the string.
 *
 * This differs from the ucase() function in lib/util.c by using the
 * libc tolower() instead of our hardcoded builtin lookup table.
 * Whether this is a good thing is unclear, but that's what the old code
 * did so I'm going to preserve it - gnb
 */
static char *message_ucase(char *s)
{
    char *p;

    for (p = s ; *p ; p++)
	if (Uislower(*p))
	    *p = toupper((int) *p);
    return s;
}

/*
 * Copy a message of 'size' bytes from 'from' to 'to',
 * ensuring minimal RFC-822 compliance.
 *
 * Caller must have initialized config_* routines (with cyrus_init) to read
 * imapd.conf before calling.
 */
int message_copy_strict(struct protstream *from, FILE *to,
		        unsigned size, int allow_null)
{
    char buf[4096+1];
    unsigned char *p, *endp;
    int r = 0;
    size_t n;
    int sawcr = 0, sawnl;
    int reject8bit = config_getswitch(IMAPOPT_REJECT8BIT);
    int munge8bit = config_getswitch(IMAPOPT_MUNGE8BIT);
    int inheader = 1, blankline = 1;

    while (size) {
	n = prot_read(from, buf, size > 4096 ? 4096 : size);
	if (!n) {
	    syslog(LOG_ERR, "IOERROR: reading message: unexpected end of file");
	    return IMAP_IOERROR;
	}

	buf[n] = '\0';

	/* Quick check for NUL in entire buffer, if we're not allowing it */
	if (!allow_null && (n != strlen(buf))) {
	    r = IMAP_MESSAGE_CONTAINSNULL;
	}

	size -= n;
	if (r) continue;

	for (p = (unsigned char *)buf, endp = p + n; p < endp; p++) {
	    if (!*p && inheader) {
		/* NUL in header is always bad */
		r = IMAP_MESSAGE_CONTAINSNULL;
	    }
	    else if (*p == '\n') {
		if (!sawcr && (inheader || !allow_null))
		    r = IMAP_MESSAGE_CONTAINSNL;
		sawcr = 0;
		if (blankline) {
		    inheader = 0;
		}
		blankline = 1;
	    }
	    else if (*p == '\r') {
		sawcr = 1;
	    }
	    else {
		sawcr = 0;
		blankline = 0;
		if (inheader && *p >= 0x80) {
		    if (reject8bit) {
			/* We have been configured to reject all mail of this
			   form. */
			if (!r) r = IMAP_MESSAGE_CONTAINS8BIT;
		    } else if (munge8bit) {
			/* We have been configured to munge all mail of this
			   form. */
			*p = 'X';
		    }
		}
	    }
	}

	fwrite(buf, 1, n, to);
    }

    if (r) return r;
    fflush(to);
    if (ferror(to) || fsync(fileno(to))) {
	syslog(LOG_ERR, "IOERROR: writing message: %m");
	return IMAP_IOERROR;
    }
    rewind(to);

    /* Go back and check headers */
    sawnl = 1;
    for (;;) {
	if (!fgets(buf, sizeof(buf), to)) {
	    return sawnl ? 0 : IMAP_MESSAGE_BADHEADER;
	}

	/* End of header section */
	if (sawnl && buf[0] == '\r') return 0;

	/* Check for valid header name */
	if (sawnl && buf[0] != ' ' && buf[0] != '\t') {
	    if (buf[0] == ':') return IMAP_MESSAGE_BADHEADER;
      if (strstr(buf, "From ") != buf)
	    for (p = (unsigned char *)buf; *p != ':'; p++) {
		if (*p <= ' ') return IMAP_MESSAGE_BADHEADER;
	    }
	}

	/* Used to be some 8bit checks here but those were moved above so that 
	   we could do something other than refuse the message.
	   Unfortunately, we still need to look for the end of the string. */
	for(p = (unsigned char*) buf; *p; p++);
	
	sawnl = (p > (unsigned char *)buf) && (p[-1] == '\n');
    }
}

int message_parse2(const char *fname, struct index_record *record,
		   struct body **bodyp)
{
    struct body *body = NULL;
    FILE *f;
    int r;

    f = fopen(fname, "r");
    if (!f) return IMAP_IOERROR;

    r = message_parse_file(f, NULL, NULL, &body);
    if (!r) {
        r = message_create_record(record, body);

	if (bodyp)
	    *bodyp = body;
	else
	    message_free_body(body);
    }

    if (f) fclose(f);

    return r;
}

/*
 * Parse the message 'infile'.
 *
 * The caller MUST free the allocated body struct.
 *
 * If msg_base/msg_len are non-NULL, the file will remain memory-mapped
 * and returned to the caller.  The caller MUST unmap the file.
 */
int message_parse_file(FILE *infile,
		       const char **msg_base, unsigned long *msg_len,
		       struct body **body)
{
    int fd = fileno(infile);
    struct stat sbuf;
    const char *tmp_base;
    unsigned long tmp_len;
    int unmap = 0, r;

    if (!msg_base) {
	unmap = 1;
	msg_base = &tmp_base;
	msg_len = &tmp_len;
    }
    *msg_base = NULL;
    *msg_len = 0;

    if (fstat(fd, &sbuf) == -1) {
	syslog(LOG_ERR, "IOERROR: fstat on new message in spool: %m");
	fatal("can't fstat message file", EC_OSFILE);
    }
    map_refresh(fd, 1, msg_base, msg_len, sbuf.st_size,
		"new message", 0);

    if (!*msg_base || !*msg_len)
	return IMAP_IOERROR; /* zero length file? */

    if (!*body) *body = (struct body *) xmalloc(sizeof(struct body));
    r = message_parse_mapped(*msg_base, *msg_len, *body);

    if (unmap) map_free(msg_base, msg_len);

    return r;
}


/*
 * Parse the message 'infile'.
 *
 * The caller MUST free the allocated body struct.
 *
 * This function differs from message_parse_file() in that we create a
 * writable buffer rather than memory-mapping the file, so that binary
 * data can be encoded into the buffer.  The file is rewritten upon
 * completion.
 *
 * XXX can we do this with mmap()?
 */
int message_parse_binary_file(FILE *infile, struct body **body)
{
    int fd = fileno(infile);
    struct stat sbuf;
    struct msg msg;
    size_t n;

    if (fstat(fd, &sbuf) == -1) {
	syslog(LOG_ERR, "IOERROR: fstat on new message in spool: %m");
	fatal("can't fstat message file", EC_OSFILE);
    }
    msg.len = sbuf.st_size;
    msg.base = xmalloc(msg.len);
    msg.offset = 0;
    msg.encode = 1;

    lseek(fd, 0L, SEEK_SET);

    n = retry_read(fd, (char*) msg.base, msg.len);
    if (n != msg.len) {
	syslog(LOG_ERR, "IOERROR: reading binary file in spool: %m");
	return IMAP_IOERROR;
    }

    if (!*body) *body = (struct body *) xmalloc(sizeof(struct body));
    message_parse_body(&msg, *body,
		       DEFAULT_CONTENT_TYPE, (strarray_t *)0);

    lseek(fd, 0L, SEEK_SET);
    n = retry_write(fd, msg.base, msg.len);

    free((char*) msg.base);

    if (n != msg.len || fsync(fd)) {
	syslog(LOG_ERR, "IOERROR: rewriting binary file in spool: %m");
	return IMAP_IOERROR;
    }

    return 0;
}

static int message_has_attachment(const struct body *body)
{
    int i;

    /* if it's multipart, if more than 2 parts or any non-text
     * parts, it has an attachment */
    if (!strcasecmp(body->type, "MULTIPART")) {
	if (body->numparts > 2)
	    return 1;
	for (i = 0; i < body->numparts; i++) {
	    if (strcasecmp(body->subpart[i].type, "TEXT"))
		return 1;
	}
    }
    /* if single part and not text, it's an attachment */
    else if (strcasecmp(body->type, "TEXT")) {
	return 1;
    }

    return 0;
}

/*
 * Parse the message at 'msg_base' of length 'msg_len'.
 */
int message_parse_mapped(const char *msg_base, unsigned long msg_len,
			 struct body *body)
{
    struct msg msg;

    msg.base = msg_base;
    msg.len = msg_len;
    msg.offset = 0;
    msg.encode = 0;

    message_parse_body(&msg, body,
		       DEFAULT_CONTENT_TYPE, (strarray_t *)0);

    message_guid_generate(&body->guid, msg_base, msg_len);

    if (message_has_attachment(body))
	body->message_flags |= FLAG_HASATTACHMENT;

    return 0;
}

static void message_find_part(struct body *body, const char *section,
			      const char **content_types,
			      const char *msg_base, unsigned long msg_len,
			      struct bodypart ***parts, int *n)
{
    int match;
    const char **type;
    char nextsection[128];

    for (match = 0, type = content_types; !match && *type; type++) {
	const char *subtype = strchr(*type, '/');
	size_t tlen = subtype ? (size_t) (subtype++ - *type) : strlen(*type);

	if ((!(*type)[0] || (tlen == strlen(body->type) &&
			     !strncasecmp(body->type, *type, tlen))) &&
	    (!subtype || !subtype[0] || !strcasecmp(body->subtype, subtype))) {
	    match = 1;
	}
    }

    if (match) {
	/* matching part, sanity check the size against the mmap'd file */
	if ((unsigned long) body->content_offset + body->content_size > msg_len) {
	    syslog(LOG_ERR, "IOERROR: body part exceeds size of message file");
	    fatal("body part exceeds size of message file", EC_OSFILE);
	}

	if (!body->decoded_body) {
	    int encoding, charset;
	    message_parse_charset(body, &encoding, &charset);
	    if (charset < 0) charset = 0; /* unknown, try ASCII */
	    body->decoded_body = charset_to_utf8(
		msg_base + body->content_offset, body->content_size,
		charset, encoding); /* returns a cstring */
	}

	/* grow the array and add the new part */
	*parts = xrealloc(*parts, (*n+2)*sizeof(struct bodypart *));
	(*parts)[*n] = xmalloc(sizeof(struct bodypart));
	strlcpy((*parts)[*n]->section, section, sizeof((*parts)[*n]->section));
	(*parts)[*n]->decoded_body = body->decoded_body;
	(*parts)[++(*n)] = NULL;
    }
    else if (!strcmp(body->type, "MULTIPART")) {
	int i;

	for (i = 0; i < body->numparts; i++) {
	    snprintf(nextsection, sizeof(nextsection), "%s.%d", section, i+1);
	    message_find_part(&body->subpart[i], nextsection, content_types,
			      msg_base, msg_len, parts, n);
	}
    }
    else if (!strcmp(body->type, "MESSAGE") &&
	     !strcmp(body->subtype, "RFC822")) {
	snprintf(nextsection, sizeof(nextsection), "%s.1", section);
	message_find_part(body->subpart, nextsection, content_types,
			  msg_base, msg_len, parts, n);
    }
}

/*
 * Fetch the bodypart(s) which match the given content_type and return
 * them as an allocated array.
 *
 * The caller MUST free the array of allocated bodypart(s).
 */
void message_fetch_part(struct message_content *msg,
		        const char **content_types,
		        struct bodypart ***parts)
{
    int n = 0;  /* running count of the number of matching parts */

    *parts = NULL;
    message_find_part(msg->body, "1", content_types,
		      msg->base, msg->len, parts, &n);
}

/*
 * Appends the message's cache information to the cache file
 * and fills in appropriate information in the index record pointed to
 * by 'record'.
 */
int message_create_record(struct index_record *record,
			  const struct body *body)
{
    if (!record->internaldate) {
	if (body->received_date &&
		config_getenum(IMAPOPT_INTERNALDATE_HEURISTIC) 
		== IMAP_ENUM_INTERNALDATE_HEURISTIC_RECEIVEDHEADER)
	    time_from_rfc822(body->received_date, &record->internaldate);
    }

    /* used for sent time searching, truncated to day with no TZ */
    if (day_from_rfc822(body->date, &record->sentdate) < 0)
	record->sentdate = 0;

    /* used for sent time sorting, full gmtime of Date: header */
    if (time_from_rfc822(body->date, &record->gmtime) < 0)
	record->gmtime = 0;

    record->size = body->header_size + body->content_size;
    record->header_size = body->header_size;
    record->content_lines = body->content_lines;
    message_guid_copy(&record->guid, &body->guid);

    /* track found attachemnts or truedomain headers */
    record->system_flags |= body->message_flags;

    message_write_cache(record, body);

    return 0;
}

static enum rfc822_header
message_header_lookup(const char *buf, const char **valp)
{
    unsigned int len = strcspn(buf, ":\r\n");
    if (buf[len] != ':')
	return RFC822_BAD;
    if (valp)
	*valp = buf+len+1;
    return rfc822_header_from_string_len(buf, len);
}


/*
 * Parse a body-part
 */
static int message_parse_body(struct msg *msg, struct body *body,
			      const char *defaultContentType,
			      strarray_t *boundaries)
{
    strarray_t newboundaries = STRARRAY_INITIALIZER;
    int sawboundary;

    memset(body, 0, sizeof(struct body));

    /* No passed-in boundary structure, create a new, empty one */
    if (!boundaries) {
	boundaries = &newboundaries;
	/* We're at top-level--set up to store cached headers */
	message_ibuf_init(&body->cacheheaders);
    }

    sawboundary = message_parse_headers(msg, body, defaultContentType,
					boundaries);

    /* Recurse according to type */
    if (strcmp(body->type, "MULTIPART") == 0) {
	if (!sawboundary) {
	    message_parse_multipart(msg, body, boundaries);
	}
    }
    else if (strcmp(body->type, "MESSAGE") == 0 &&
	strcmp(body->subtype, "RFC822") == 0) {
	body->subpart = (struct body *)xmalloc(sizeof(struct body));

	if (sawboundary) {
	    memset(body->subpart, 0, sizeof(struct body));
	    message_parse_type(DEFAULT_CONTENT_TYPE, body->subpart);
	}
	else {
	    message_parse_body(msg, body->subpart,
			       DEFAULT_CONTENT_TYPE, boundaries);

	    /* Calculate our size/lines information */
	    body->content_size = body->subpart->header_size +
	      body->subpart->content_size;
	    body->content_lines = body->subpart->header_lines +
	      body->subpart->content_lines;

	    /* Move any enclosing boundary information up to our level */
	    body->boundary_size = body->subpart->boundary_size;
	    body->boundary_lines = body->subpart->boundary_lines;
	}
    }
    else {
	if (!sawboundary) {
	    message_parse_content(msg, body, boundaries);
	}
    }

    /* Free up boundary storage if necessary */
    strarray_fini(&newboundaries);

    return 0;
}

/*
 * Parse the headers of a body-part
 */
#define HEADGROWSIZE 1000
static int message_parse_headers(struct msg *msg, struct body *body,
				 const char *defaultContentType,
				 strarray_t *boundaries)
{
    static int alloced = 0;
    static char *headers;
    int left, len;
    char *next;
    int sawboundary = 0;
    int maxlines = config_getint(IMAPOPT_MAXHEADERLINES);
    int have_max = 0;
    const char *value;

    body->header_offset = msg->offset;

    if (!alloced) {
	headers = xmalloc(alloced = HEADGROWSIZE);
    }

    next = headers;
    *next++ = '\n';		/* Leading newline to prime the pump */
    left = alloced - 3;		/* Allow for leading newline, added CR */
				/*  and trailing NUL */

    /* Slurp up all of the headers into 'headers' */
    while (message_getline(next, left, msg) &&
	   (next[-1] != '\n' ||
	    (*next != '\r' || next[1] != '\n'))) {

	len = strlen(next);

	if (next[-1] == '\n' && *next == '-' &&
	    message_pendingboundary(next, len, boundaries)) {
	    body->boundary_size = len;
	    body->boundary_lines++;
	    if (next - 1 > headers) {
		body->boundary_size += 2;
		body->boundary_lines++;
		next[-2] = '\0';
	    }
	    else {
		*next = '\0';
	    }
	    sawboundary = 1;
	    break;
	}

	left -= len;
	next += len;

	/* Allocate more header space if necessary */
	if (left < 100) {
	    len = next - headers;
	    alloced += HEADGROWSIZE;
	    left += HEADGROWSIZE;
	    headers = xrealloc(headers, alloced);
	    next = headers + len;
	}
    }

    body->content_offset = msg->offset;
    body->header_size = strlen(headers+1);

    /* Scan over the slurped-up headers for interesting header information */
    body->header_lines = -1;	/* Correct for leading newline */
    for (next = headers; *next; next++) {
	if (*next == '\n') {
	    body->header_lines++;

	    /* if we're skipping, skip now */
	    if (have_max) continue;

	    /* check if we've hit a limit and flag it */
	    if (maxlines && body->header_lines > maxlines) {
		syslog(LOG_ERR, "ERROR: message has more than %d header lines, not caching any more",
		       maxlines);
		have_max = 1;
		continue;
	    }

	    /* Check for headers in generic cache */
	    if (body->cacheheaders.start &&
		(next[1] != ' ') && (next[1] != '\t') &&
		mailbox_cached_header_inline(next+1) != BIT32_MAX) {
		    message_parse_header(next+1, &body->cacheheaders);
	    }

	    switch (message_header_lookup(next+1, &value)) {
	    case RFC822_BCC:
		message_parse_address(value, &body->bcc);
		break;
	    case RFC822_CC:
		message_parse_address(value, &body->cc);
		break;
	    case RFC822_CONTENT_DESCRIPTION:
		message_parse_string(value, &body->description);
		break;
	    case RFC822_CONTENT_DISPOSITION:
		message_parse_disposition(value, body);
		break;
	    case RFC822_CONTENT_ID:
		message_parse_string(value, &body->id);
		break;
	    case RFC822_CONTENT_LANGUAGE:
		message_parse_language(value, &body->language);
		break;
	    case RFC822_CONTENT_LOCATION:
		message_parse_string(value, &body->location);
		break;
	    case RFC822_CONTENT_MD5:
		message_parse_string(value, &body->md5);
		break;
	    case RFC822_CONTENT_TRANSFER_ENCODING:
		message_parse_encoding(value, &body->encoding);

		/* If we're encoding binary, replace "binary"
		   with "base64" in CTE header body */
		if (msg->encode &&
		    !strcmp(body->encoding, "BINARY")) {
		    char *p = (char*)
			stristr(msg->base + body->header_offset +
				(next - headers) + 27,
				"binary");
		    memcpy(p, "base64", 6);
		}
		break;
	    case RFC822_CONTENT_TYPE:
		message_parse_type(value, body);
		break;
	    case RFC822_DATE:
		message_parse_string(value, &body->date);
		break;
	    case RFC822_FROM:
		message_parse_address(value, &body->from);
		break;
	    case RFC822_IN_REPLY_TO:
		message_parse_string(value, &body->in_reply_to);
		break;
	    case RFC822_MESSAGE_ID:
		message_parse_string(value, &body->message_id);
		break;
	    case RFC822_REPLY_TO:
		message_parse_address(value, &body->reply_to);
		break;
	    case RFC822_RECEIVED:
		message_parse_received_date(value, &body->received_date);
		break;
	    case RFC822_REFERENCES:
		message_parse_string(value, &body->references);
		break;
	    case RFC822_SUBJECT:
		message_parse_string(value, &body->subject);
		break;
	    case RFC822_SENDER:
		message_parse_address(value, &body->sender);
		break;
	    case RFC822_TO:
		message_parse_address(value, &body->to);
		break;
	    case RFC822_X_DELIVEREDINTERNALDATE:
		/* Explicit x-deliveredinternaldate overrides received: headers */
		if (body->received_date) {
		    free(body->received_date);
		    body->received_date = 0;
		}
		message_parse_string(value, &body->received_date);
		break;
	    case RFC822_X_TRUEDOMAIN:
		/* only want to look at the top level */
		if (boundaries->count == 0 && strstr(value, "True"))
		    body->message_flags |= FLAG_HASTRUEDOMAIN;
		break;
	    default:
		break;
	    } /* switch() */
	} /* if (*next == '\n') */
    }

    /* If didn't find Content-Type: header, use the passed-in default type */
    if (!body->type) {
	message_parse_type(defaultContentType, body);
    }
    return sawboundary;
}

/*
 * Parse a list of RFC-822 addresses from a header, appending them
 * to the address list pointed to by 'addrp'.
 */
static void message_parse_address(const char *hdr, struct address **addrp)
{
    char *hdrend, hdrendchar = '\0';

    /* Find end of header */
    hdrend = (char *)hdr;
    do {
	hdrend = strchr(hdrend+1, '\n');
    } while (hdrend && (hdrend[1] == ' ' || hdrend[1] == '\t'));

    /* Put a NUL character at the end of header */
    /* gnb:TODO this is evil and should be stopped */
    if (hdrend) {
	if (hdrend > hdr && hdrend[-1] == '\r') hdrend--;
	hdrendchar = *hdrend;
	*hdrend = '\0';
    }

    parseaddr_list(hdr, addrp);

    /* Put character at end of header back */
    if (hdrend) *hdrend = hdrendchar;
}

/*
 * Parse a Content-Transfer-Encoding from a header.
 */
static void message_parse_encoding(const char *hdr, char **hdrp)
{
    int len;
    const char *p;

    /* Ignore if we already saw one of these headers */
    if (*hdrp) return;

    /* Skip leading whitespace, ignore header if blank */
    message_parse_rfc822space(&hdr);
    if (!hdr) return;

    /* Find end of encoding token */
    for (p = hdr; *p && !Uisspace(*p) && *p != '('; p++) {
	if (*p < ' ' || strchr(TSPECIALS, *p)) return;
    }
    len = p - hdr;

    /* Skip trailing whitespace, ignore header if trailing garbage */
    message_parse_rfc822space(&p);
    if (p) return;

    /* Save encoding token */
    *hdrp = message_ucase(xstrndup(hdr, len));
}

/* 
 * parse a charset and encoding out of a body structure
 */
static void message_parse_charset(const struct body *body,
				  int *e_ptr, int *c_ptr)
{
    int encoding = ENCODING_NONE;
    int charset = 0;
    struct param *param;

    if (body->encoding) {
	switch (body->encoding[0]) {
	case '7':
	case '8':
	    if (!strcmp(body->encoding+1, "BIT")) 
		encoding = ENCODING_NONE;
	    else 
		encoding = ENCODING_UNKNOWN;
	    break;

	case 'B':
	    if (!strcmp(body->encoding, "BASE64")) 
		encoding = ENCODING_BASE64;
	    else if (!strcmp(body->encoding, "BINARY"))
		encoding = ENCODING_NONE;
	    else 
		encoding = ENCODING_UNKNOWN;
	    break;

	case 'Q':
	    if (!strcmp(body->encoding, "QUOTED-PRINTABLE"))
		encoding = ENCODING_QP;
	    else 
		encoding = ENCODING_UNKNOWN;
	    break;

	default:
	    encoding = ENCODING_UNKNOWN;
	}
    }

    if (!body->type || !strcmp(body->type, "TEXT")) {
	for (param = body->params; param; param = param->next) {
	    if (!strcasecmp(param->attribute, "charset")) {
		charset = charset_lookupname(param->value);
		break;
	    }
	}
    }
    else if (!strcmp(body->type, "MESSAGE")) {
	if (!strcmp(body->subtype, "RFC822"))
	    charset = -1;
	encoding = ENCODING_NONE;
    }
    else
	charset = -1;

    if (e_ptr) *e_ptr = encoding;
    if (c_ptr) *c_ptr = charset;
}

/*
 * Parse an uninterpreted header
 */
static void message_parse_string(const char *hdr, char **hdrp)
{
    const char *hdrend;
    char *he;

    /* Ignore if we already saw one of these headers */
    if (*hdrp) return;

    /* Skip initial whitespace */
    while (*hdr == ' ' || *hdr == '\t') hdr++;

    /* Find end of header */
    hdrend = hdr;
    do {
	hdrend = strchr(hdrend+1, '\n');
    } while (hdrend && (hdrend[1] == ' ' || hdrend[1] == '\t'));
    if (hdrend) {
	if (hdrend > hdr && hdrend[-1] == '\r') hdrend--;
    }
    else {
	hdrend = hdr + strlen(hdr);
    }

    /* Save header value */
    *hdrp = xstrndup(hdr, (hdrend - hdr));

    /* Un-fold header (overlapping buffers, use memmove) */
    he = *hdrp;
    while ((he = strchr(he, '\n'))!=NULL) {
	if (he > *hdrp && he[-1] == '\r') {
	    he--;
	    memmove(he, he+2, strlen(he+2)+1);
	}
	else {
	    memmove(he, he+1, strlen(he+1)+1);
	}
    }
}

/*
 * Cache a header
 */
static void
message_parse_header(const char *hdr, struct ibuf *ibuf)
{
    int len;
    const char *hdrend;

    /* Find end of header */
    hdrend = hdr;
    do {
	hdrend = strchr(hdrend+1, '\n');
    } while (hdrend && (hdrend[1] == ' ' || hdrend[1] == '\t'));
    if (hdrend) {
	if (hdrend > hdr && hdrend[-1] == '\r') hdrend--;
    }
    else {
	hdrend = hdr + strlen(hdr);
    }

    /* Save header value */
    len = hdrend - hdr;
    message_ibuf_ensure(ibuf, len+2);
    strncpy(ibuf->end, hdr, len);
    ibuf->end += len;
    *(ibuf->end)++ = '\r';
    *(ibuf->end)++ = '\n';
}

/*
 * Parse a Content-Type from a header.
 */
static void message_parse_type(const char *hdr, struct body *body)
{
    const char *type;
    int typelen;
    const char *subtype;
    int subtypelen;

    /* Ignore if we already saw one of these headers */
    if (body->type) return;

    /* Skip leading whitespace, ignore header if blank */
    message_parse_rfc822space(&hdr);
    if (!hdr) return;

    /* Find end of type token */
    type = hdr;
    for (; *hdr && !Uisspace(*hdr) && *hdr != '/' && *hdr != '('; hdr++) {
	if (*hdr < ' ' || strchr(TSPECIALS, *hdr)) return;
    }
    typelen = hdr - type;

    /* Skip whitespace after type */
    message_parse_rfc822space(&hdr);
    if (!hdr) return;

    /* Ignore header if no '/' character */
    if (*hdr++ != '/') return;

    /* Skip whitespace before subtype, ignore header if no subtype */
    message_parse_rfc822space(&hdr);
    if (!hdr) return;

    /* Find end of subtype token */
    subtype = hdr;
    for (; *hdr && !Uisspace(*hdr) && *hdr != ';' && *hdr != '('; hdr++) {
	if (*hdr < ' ' || strchr(TSPECIALS, *hdr)) return;
    }
    subtypelen = hdr - subtype;

    /* Skip whitespace after subtype */
    message_parse_rfc822space(&hdr);

    /* Ignore header if not at end of header or parameter delimiter */
    if (hdr && *hdr != ';') return;

    /* Save content type & subtype */
    body->type = message_ucase(xstrndup(type, typelen));
    body->subtype = message_ucase(xstrndup(subtype, subtypelen));

    /* Parse parameter list */
    if (hdr) {
	message_parse_params(hdr+1, &body->params);
	message_fold_params(&body->params);
    }
}

/*
 * Parse a Content-Disposition from a header.
 */
/* static */ void message_parse_disposition(const char *hdr, struct body *body)
{
    const char *disposition;
    int dispositionlen;

    /* Ignore if we already saw one of these headers */
    if (body->disposition) return;

    /* Skip leading whitespace, ignore header if blank */
    message_parse_rfc822space(&hdr);
    if (!hdr) return;

    /* Find end of disposition token */
    disposition = hdr;
    for (; *hdr && !Uisspace(*hdr) && *hdr != ';' && *hdr != '('; hdr++) {
	if (*hdr < ' ' || strchr(TSPECIALS, *hdr)) return;
    }
    dispositionlen = hdr - disposition;

    /* Skip whitespace after type */
    message_parse_rfc822space(&hdr);

    /* Ignore header if not at end of header or parameter delimiter */
    if (hdr && *hdr != ';') return;

    /* Save content disposition */
    body->disposition = message_ucase(xstrndup(disposition, dispositionlen));

    /* Parse parameter list */
    if (hdr) {
	message_parse_params(hdr+1, &body->disposition_params);
	message_fold_params(&body->disposition_params);
    }
}

/*
 * Parse a parameter list from a header
 */
static void message_parse_params(const char *hdr, struct param **paramp)
{
    struct param *param;
    const char *attribute;
    int attributelen;
    const char *value;
    int valuelen;
    char *p;

    for (;;) {
	/* Skip over leading whitespace */
	message_parse_rfc822space(&hdr);
	if (!hdr) return;

	/* Find end of attribute */
	attribute = hdr;
	for (; *hdr && !Uisspace(*hdr) && *hdr != '=' && *hdr != '('; hdr++) {
	    if (*hdr < ' ' || strchr(TSPECIALS, *hdr)) return;
	}
	attributelen = hdr - attribute;

	/* Skip whitespace after attribute */
	message_parse_rfc822space(&hdr);
	if (!hdr) return;

	/* Ignore param if no '=' character */
	if (*hdr++ != '=') return;

	/* Skip whitespace before value */
	message_parse_rfc822space(&hdr);
	if (!hdr) return;

	/* Find end of value */
	value = hdr;
	if (*hdr == '\"') {
	    hdr++;
	    while (*hdr && *hdr != '\"') {
		if (*hdr == '\\') {
		    hdr++;
		    if (!*hdr) return;
		}
		if (*hdr == '\r') {
		    if (hdr[1] == '\n' && (hdr[2] == ' ' || hdr[2] == '\t')) hdr += 2;
 		    else return;
		}
		hdr++;
	    }
	    if (!*hdr++) return;
	}
	else {
	    for (; *hdr && !Uisspace(*hdr) && *hdr != ';' && *hdr != '('; hdr++) {
		if (*hdr < ' ' || strchr(TSPECIALS, *hdr)) return;
	    }
	}
	valuelen = hdr - value;

	/* Skip whitespace after value */
	message_parse_rfc822space(&hdr);

	/* Ignore parameter if not at end of header or parameter delimiter */
	if (hdr && *hdr++ != ';') return;
		  
	/* Save attribute/value pair */
	*paramp = param = (struct param *)xzmalloc(sizeof(struct param));
	param->attribute = message_ucase(xstrndup(attribute, attributelen));
	param->value = xmalloc(valuelen + 1);
	if (*value == '\"') {
	    p = param->value;
	    value++;
	    while (*value != '\"') {
		if (*value == '\\') value++;
		else if (*value == '\r') value += 2;
		*p++ = *value++;
	    }
	    *p = '\0';
	}
	else {
	    strlcpy(param->value, value, valuelen + 1);
	}

	/* Get ready to parse the next parameter */
	paramp = &param->next;
    }
}

/*
 * Decode RFC-2231 parameter continuations
 *
 * Algorithm: Run down the list of parameters looking for
 * an attribute of the form "foo*0" or "foo*0*".  When we find 
 * such an attribute, we look for "foo*1"/"foo*1*", "foo*2"/"foo*2*"
 * etc, appending each value to that of "foo*0" and then removing the
 * parameter we just appended from the list.  When appending values,
 * if either parameter has extended syntax, we have to convert the other
 * value from simple to extended syntax.  At the end, we change the name
 * of "foo*0"/"foo*0*" to either "foo" or "foo*", depending on whether
 * the value has extended syntax or not.
 */
static void message_fold_params(struct param **params)
{
    struct param *thisparam;	/* The "foo*1" param we're folding */
    struct param **continuation; /* Pointer to the "foo*2" param */
    struct param *tmpparam;	/* Placeholder for removing "foo*2" */
    char *asterisk;
    int section;
    int is_extended;
    char sectionbuf[5];
    int attributelen, sectionbuflen;
    char *from, *to;

    for (thisparam = *params; thisparam; thisparam = thisparam->next) {
	asterisk = strchr(thisparam->attribute, '*');
	if (asterisk && asterisk[1] == '0' &&
	    (!asterisk[2] || (asterisk[2] == '*' && !asterisk[3]))) {
	    /* An initial section.  Find and collect the rest */
	    is_extended = (asterisk[2] == '*');
	    *asterisk = '\0';
	    attributelen = asterisk - thisparam->attribute;
	    section = 1;
	    for (;;) {
		if (section == 100) break;
		sectionbuf[0] = '*';
		if (section > 9) {
		    sectionbuf[1] = section/10 + '0';
		    sectionbuf[2] = section%10 + '0';
		    sectionbuf[3] = '\0';
		    sectionbuflen = 3;
		}
		else {
		    sectionbuf[1] = section + '0';
		    sectionbuf[2] = '\0';
		    sectionbuflen = 2;
		}

		/* Find the next continuation */
		for (continuation = params; *continuation;
		     continuation = &((*continuation)->next)) {
		    if (!strncmp((*continuation)->attribute, thisparam->attribute,
				 attributelen) &&
			!strncmp((*continuation)->attribute + attributelen,
				 sectionbuf, sectionbuflen) &&
			((*continuation)->attribute[attributelen+sectionbuflen] == '\0' ||
			 ((*continuation)->attribute[attributelen+sectionbuflen] == '*' && (*continuation)->attribute[attributelen+sectionbuflen+1] == '\0'))) {
			break;
		    }
		}

		/* No more continuations to find */
		if (!*continuation) break;
		
		if ((*continuation)->attribute[attributelen+sectionbuflen] == '\0') {
		    /* Continuation is simple */
		    if (is_extended) {
			/* Have to re-encode continuation value */
			thisparam->value =
			    xrealloc(thisparam->value,
				     strlen(thisparam->value) +
				     3*strlen((*continuation)->value) + 1);
			from = (*continuation)->value;
			to = thisparam->value + strlen(thisparam->value);
			while (*from) {
			    if (*from <= ' ' || *from >= 0x7f ||
				*from == '*' || *from == '\'' ||
				*from == '%' || strchr(TSPECIALS, *from)) {
				*to++ = '%';
				to += bin_to_hex(from, 1, to, BH_UPPER);
			    } else {
				*to++ = *from;
			    }
			    from++;
			}
			*to++ = '\0';
		    }
		    else {
			thisparam->value =
			    xrealloc(thisparam->value,
				     strlen(thisparam->value) +
				     strlen((*continuation)->value) + 1);
			from = (*continuation)->value;
			to = thisparam->value + strlen(thisparam->value);
			while ((*to++ = *from++)!= 0)
			    { }
		    }
		}
		else {
		    /* Continuation is extended */
		    if (is_extended) {
			thisparam->value =
			    xrealloc(thisparam->value,
				     strlen(thisparam->value) +
				     strlen((*continuation)->value) + 1);
			from = (*continuation)->value;
			to = thisparam->value + strlen(thisparam->value);
			while ((*to++ = *from++) != 0)
			    { }
		    }
		    else {
			/* Have to re-encode thisparam value */
			char *tmpvalue =
			    xmalloc(2 + 3*strlen(thisparam->value) +
				    strlen((*continuation)->value) + 1);

			from = thisparam->value;
			to = tmpvalue;
			*to++ = '\''; /* Unspecified charset */
			*to++ = '\''; /* Unspecified language */
			while (*from) {
			    if (*from <= ' ' || *from >= 0x7f ||
				*from == '*' || *from == '\'' ||
				*from == '%' || strchr(TSPECIALS, *from)) {
				*to++ = '%';
				to += bin_to_hex(from, 1, to, BH_UPPER);
			    } else {
				*to++ = *from;
			    }
			    from++;
			}
			from = (*continuation)->value;

			while ((*to++ = *from++)!=0)
			    { }

			free(thisparam->value);
			thisparam->value = tmpvalue;
			is_extended = 1;
		    }
		}

		/* Remove unneeded continuation */
		free((*continuation)->attribute);
		free((*continuation)->value);
		tmpparam = *continuation;
		*continuation = (*continuation)->next;
		free(tmpparam);
		section++;
	    }

	    /* Fix up attribute name */
	    if (is_extended) {
		asterisk[0] = '*';
		asterisk[1] = '\0';
	    } else {
		asterisk[0] = '\0';
	    }
	}
    }
}	 


/*
 * Parse a language list from a header
 */
static void message_parse_language(const char *hdr, struct param **paramp)
{
    struct param *param;
    const char *value;
    int valuelen;

    for (;;) {
	/* Skip over leading whitespace */
	message_parse_rfc822space(&hdr);
	if (!hdr) return;

	/* Skip whitespace before value */
	message_parse_rfc822space(&hdr);
	if (!hdr) return;

	/* Find end of value */
	value = hdr;
	for (; *hdr && !Uisspace(*hdr) && *hdr != ',' && *hdr != '('; hdr++) {
	    if (*hdr != '-' && !Uisalpha((*hdr))) return;
	}
	valuelen = hdr - value;

	/* Skip whitespace after value */
	message_parse_rfc822space(&hdr);

	/* Ignore parameter if not at end of header or language delimiter */
	if (hdr && *hdr++ != ',') return;
		  
	/* Save value pair */
	*paramp = param = (struct param *)xzmalloc(sizeof(struct param));
	param->value = message_ucase(xstrndup(value, valuelen));

	/* Get ready to parse the next parameter */
	paramp = &param->next;
    }
}

/*
 * Skip over RFC-822 whitespace and comments
 */
static void message_parse_rfc822space(const char **s)
{
    const char *p = *s;
    int commentlevel = 0;

    if (!p) return;
    while (*p && (Uisspace(*p) || *p == '(')) {
	if (*p == '\n') {
	    p++;
	    if (*p != ' ' && *p != '\t') {
		*s = 0;
		return;
	    }
	}
	else if (*p == '(') {
	    p++;
	    commentlevel++;
	    while (commentlevel) {
		switch (*p) {
		case '\n':
		    p++;
		    if (*p == ' ' || *p == '\t') break;
		    /* FALL THROUGH */
		case '\0':
		    *s = 0;
		    return;
		    
		case '\\':
		    p++;
		    break;

		case '(':
		    commentlevel++;
		    break;

		case ')':
		    commentlevel--;
		    break;
		}
		p++;
	    }
	}
	else p++;
    }
    if (*p == 0) {
	*s = 0;
    }
    else {
	*s = p;
    }
}

/*
 * Parse the content of a MIME multipart body-part
 */
static void message_parse_multipart(struct msg *msg, struct body *body,
				    strarray_t *boundaries)
{
    struct body preamble, epilogue;
    struct param *boundary;
    const char *defaultContentType = DEFAULT_CONTENT_TYPE;
    int i, depth;

    memset(&preamble, 0, sizeof(struct body));
    memset(&epilogue, 0, sizeof(struct body));
    if (strcmp(body->subtype, "DIGEST") == 0) {
	defaultContentType = "MESSAGE/RFC822";
    }

    /* Find boundary id */
    boundary = body->params;
    while(boundary && strcmp(boundary->attribute, "BOUNDARY") != 0) {
	boundary = boundary->next;
    }
    
    if (!boundary) {
	/* Invalid MIME--treat as zero-part multipart */
	message_parse_content(msg, body, boundaries);
	return;
    }

    /* Add the new boundary id */
    strarray_append(boundaries, boundary->value);
    depth = boundaries->count;

    /* Parse preamble */
    message_parse_content(msg, &preamble, boundaries);

    /* Parse the component body-parts */
    while (boundaries->count == depth) {
	body->subpart = (struct body *)xrealloc((char *)body->subpart,
				 (body->numparts+1)*sizeof(struct body));
	message_parse_body(msg, &body->subpart[body->numparts++],
			   defaultContentType, boundaries);
	if (msg->offset == msg->len &&
	    body->subpart[body->numparts-1].boundary_size == 0) {
	    /* hit the end of the message, therefore end all pending
	       multiparts */
	    boundaries->count = 0;
	}
    }

    if (boundaries->count == depth-1) {
	/* Parse epilogue */
	message_parse_content(msg, &epilogue, boundaries);
    }
    else if (body->numparts) {
	/*
	 * We hit the boundary of an enclosing multipart while parsing
	 * a component body-part.  Move the enclosing boundary information
	 * up to our level.
	 */
	body->boundary_size = body->subpart[body->numparts-1].boundary_size;
	body->boundary_lines = body->subpart[body->numparts-1].boundary_lines;
	body->subpart[body->numparts-1].boundary_size = 0;
	body->subpart[body->numparts-1].boundary_lines = 0;
    }
    else {
	/*
	 * We hit the boundary of an enclosing multipart while parsing
	 * the preamble.  Move the enclosing boundary information
	 * up to our level.
	 */
	body->boundary_size = preamble.boundary_size;
	body->boundary_lines = preamble.boundary_lines;
	preamble.boundary_size = 0;
	preamble.boundary_lines = 0;
    }

    /*
     * Calculate our size/lines information
     */
    body->content_size = preamble.content_size + preamble.boundary_size;
    body->content_lines = preamble.content_lines + preamble.boundary_lines;
    for (i=0; i< body->numparts; i++) {
	body->content_size += body->subpart[i].header_size +
	  body->subpart[i].content_size +
	  body->subpart[i].boundary_size;
	body->content_lines += body->subpart[i].header_lines +
	  body->subpart[i].content_lines +
	  body->subpart[i].boundary_lines;
    }
    body->content_size += epilogue.content_size;
    body->content_lines += epilogue.content_lines;

    /*
     * Move any enclosing boundary information up to our level.
     */
    body->boundary_size += epilogue.boundary_size;
    body->boundary_lines += epilogue.boundary_lines;
}

/*
 * Parse the content of a generic body-part
 */
static void message_parse_content(struct msg *msg, struct body *body,
				  strarray_t *boundaries)
{
    const char *line, *endline;
    unsigned long s_offset = msg->offset;
    int encode;
    int len;

    /* Should we encode a binary part? */
    encode = msg->encode &&
	body->encoding && !strcasecmp(body->encoding, "binary");

    while (msg->offset < msg->len) {
	line = msg->base + msg->offset;
	endline = memchr(line, '\n', msg->len - msg->offset);
	if (endline) {
	    endline++;
	}
	else {
	    endline = msg->base + msg->len;
	}
	len = endline - line;
	msg->offset += len;

	if (line[0] == '-' && line[1] == '-' &&
	    message_pendingboundary(line, len, boundaries)) {
	    body->boundary_size = len;
	    body->boundary_lines++;
	    if (body->content_lines) {
		body->content_lines--;
		body->boundary_lines++;
	    }
	    if (body->content_size) {
		body->content_size -= 2;
		body->boundary_size += 2;
	    }
	    break;
	}

	body->content_size += len;

	/* Count the content lines, unless we're encoding
	   (we always count blank lines) */
	if (endline[-1] == '\n' &&
	    (!encode || line[0] == '\r')) {
	    body->content_lines++;
	}
    }

    if (encode) {
	size_t b64_size;
	int b64_lines, delta;

	/* Determine encoded size */
	charset_encode_mimebody(NULL, body->content_size, NULL,
				&b64_size, NULL);

	delta = b64_size - body->content_size;

	/* Realloc buffer to accomodate encoding overhead */
	msg->base = xrealloc((char*) msg->base, msg->len + delta);

	/* Shift content and remaining data by delta */
	memmove((char*) msg->base + s_offset + delta, msg->base + s_offset,
		msg->len - s_offset);

	/* Encode content into buffer at current position */
	charset_encode_mimebody(msg->base + s_offset + delta,
				body->content_size,
				(char*) msg->base + s_offset,
				NULL, &b64_lines);

	/* Adjust buffer position and length to account for encoding */
	msg->offset += delta;
	msg->len += delta;

	/* Adjust body structure to account for encoding */
	strcpy(body->encoding, "BASE64");
	body->content_size = b64_size;
	body->content_lines += b64_lines;
    }
}

static void message_parse_received_date(const char *hdr, char **hdrp)
{
  char *curp, *hdrbuf = 0;

  /* Ignore if we already saw one of these headers */
  if (*hdrp) return;

  /* Copy header to temp buffer */
  message_parse_string(hdr, &hdrbuf);

  /* From rfc2822, 3.6.7
   *   received = "Received:" name-val-list ";" date-time CRLF
   * So scan backwards for ; and assume everything after is a date.
   * Failed parsing will return 0, and we'll use time() elsewhere
   * instead anyway
   */
  curp = hdrbuf + strlen(hdrbuf) - 1;
  while (curp > hdrbuf && *curp != ';')
    curp--;

  /* Didn't find ; - fill in hdrp so we don't look at next received header */
  if (curp == hdrbuf) {
    *hdrp = hdrbuf;
    return;
  }

  /* Found it, copy out date string part */
  curp++;
  message_parse_string(curp, hdrp);
  free(hdrbuf);
}


/*
 * Read a line from 'msg' (or at most 'n' characters) into 's'
 */
static char *message_getline(char *s, unsigned n, struct msg *msg)
{
    char *rval = s;

    if (n == 0) return 0;
    n--;			/* Allow for terminating nul */

    while (msg->offset < msg->len && n--) {
	if ((*s++ = msg->base[msg->offset++]) == '\n') break;
    }
    *s = '\0';

    if (s == rval) return 0;
    return rval;
}


/*
 * Return nonzero if s is an enclosing boundary delimiter.
 * If we hit a terminating boundary, the integer pointed to by
 * 'boundaryct' is modified appropriately.
 */
static int message_pendingboundary(const char *s, int slen,
				   strarray_t *boundaries)
{
    int i, len;
    int rfc2046_strict = config_getswitch(IMAPOPT_RFC2046_STRICT);
    const char *bbase;
    int blen;

    /* skip initial '--' */
    if (slen < 2) return 0;
    if (s[0] != '-' || s[1] != '-') return 0;
    bbase = s + 2;
    blen = slen - 2;

    for (i = 0; i < boundaries->count ; ++i) {
	len = strlen(boundaries->data[i]);
	/* basic sanity check and overflow protection */
	if (blen < len) continue;

	if (!strncmp(bbase, boundaries->data[i], len)) {
	    /* trailing '--', it's the end of this part */
	    if (blen >= len+2 && bbase[len] == '-' && bbase[len+1] == '-')
		strarray_truncate(boundaries, i);
	    else if (!rfc2046_strict && blen > len+1 &&
		     bbase[len] && !Uisspace(bbase[len])) {
		/* Allow substring matches in the boundary.
		 *
		 * If rfc2046_strict is enabled, boundaries containing
		 * other boundaries as substrings will be treated as identical
		 * (per RFC 2046 section 5.1.1).  Note that this will
		 * break some messages created by Eudora 5.1 (and earlier).
		 */
		continue;
	    }
	    return 1;
	}
    }
    return 0;
}

/*
 * Write the cache information for the message parsed to 'body'
 * to 'outfile'.
 */
int message_write_cache(struct index_record *record, const struct body *body)
{
    static struct buf cacheitem_buffer;
    struct ibuf ib[10];
    struct body toplevel;
    char *subject;
    int len;
    int i;

    /* initialise data structures */
    buf_reset(&cacheitem_buffer);
    for (i = 0; i < 10; i++)
	message_ibuf_init(&ib[i]);

    toplevel.type = "MESSAGE";
    toplevel.subtype = "RFC822";
    /* we cast away const because we know that we're only using
     * toplevel.subpart as const in message_write_section(). */
    toplevel.subpart = (struct body *)body;

    subject = charset_decode_mimeheader(body->subject);

    /* copy into ibufs */
    message_write_envelope(&ib[CACHE_ENVELOPE], body);
    message_write_body(&ib[CACHE_BODYSTRUCTURE], body, 1);
    message_ibuf_copy(&ib[CACHE_HEADERS], &body->cacheheaders); 
    message_write_body(&ib[CACHE_BODY], body, 0);
    message_write_section(&ib[CACHE_SECTION], &toplevel);
    message_write_searchaddr(&ib[CACHE_FROM], body->from);
    message_write_searchaddr(&ib[CACHE_TO], body->to);
    message_write_searchaddr(&ib[CACHE_CC], body->cc);
    message_write_searchaddr(&ib[CACHE_BCC], body->bcc);
    message_write_nstring(&ib[CACHE_SUBJECT], subject);

    free(subject);

    /* append the records to the buffer */
    for (i = 0; i < 10; i++) {
	message_ibuf_pad(&ib[i]);
	record->crec.item[i].len = ib[i].end - ib[i].start;
	buf_appendbit32(&cacheitem_buffer, record->crec.item[i].len);
	record->crec.item[i].offset = buf_len(&cacheitem_buffer);
	buf_appendmap(&cacheitem_buffer, ib[i].start, (record->crec.item[i].len + 3) & ~3);
	message_ibuf_free(&ib[i]);
    }

    len = buf_len(&cacheitem_buffer);

    /* copy the fields into the message */
    record->cache_offset = 0; /* calculate on write! */
    record->cache_version = MAILBOX_CACHE_MINOR_VERSION;
    record->cache_crc = crc32_map(cacheitem_buffer.s, len); /* XXX - hacky */
    record->crec.base = &cacheitem_buffer;
    record->crec.offset = 0; /* we're at the start of the buffer */
    record->crec.len = len;

    return 0;
}

/* Append character 'c' to 'ibuf' */
#define PUTIBUF(ibuf,c) (((void)((ibuf)->end<(ibuf)->last || message_ibuf_ensure((ibuf),1))),(*((ibuf)->end)++ = (c)))

/*
 * Write the IMAP envelope for 'body' to 'ibuf'
 */
static void message_write_envelope(struct ibuf *ibuf, const struct body *body)
{
    PUTIBUF(ibuf, '(');
    message_write_nstring(ibuf, body->date);
    PUTIBUF(ibuf, ' ');
    message_write_nstring(ibuf, body->subject);
    PUTIBUF(ibuf, ' ');
    message_write_address(ibuf, body->from);
    PUTIBUF(ibuf, ' ');
    message_write_address(ibuf, body->sender ? body->sender : body->from);
    PUTIBUF(ibuf, ' ');
    message_write_address(ibuf, body->reply_to ? body->reply_to : body->from);
    PUTIBUF(ibuf, ' ');
    message_write_address(ibuf, body->to);
    PUTIBUF(ibuf, ' ');
    message_write_address(ibuf, body->cc);
    PUTIBUF(ibuf, ' ');
    message_write_address(ibuf, body->bcc);
    PUTIBUF(ibuf, ' ');
    message_write_nstring(ibuf, body->in_reply_to);
    PUTIBUF(ibuf, ' ');
    message_write_nstring(ibuf, body->message_id);
    PUTIBUF(ibuf, ')');
}

/*
 * Write the BODY (if 'newformat' is zero) or BODYSTRUCTURE
 * (if 'newformat' is nonzero) for 'body' to 'ibuf'.
 */
static void message_write_body(struct ibuf *ibuf, const struct body *body,
			       int newformat)
{
    struct param *param;

    if (strcmp(body->type, "MULTIPART") == 0) {
	int i;

	/* 0-part multiparts are illegal--convert to 0-len text parts */
	if (body->numparts == 0) {
	    static struct body zerotextbody;

	    if (!zerotextbody.type) {
		message_parse_type(DEFAULT_CONTENT_TYPE, &zerotextbody);
	    }
	    message_write_body(ibuf, &zerotextbody, newformat);
	    return;
	}

	/* Multipart types get a body_multipart */
	PUTIBUF(ibuf, '(');
	for (i = 0; i < body->numparts; i++) {
	    message_write_body(ibuf, &body->subpart[i], newformat);
	}
	PUTIBUF(ibuf, ' ');
	message_write_nstring(ibuf, body->subtype);

	if (newformat) {
	    PUTIBUF(ibuf, ' ');
	    if ((param = body->params)!=NULL) {
		PUTIBUF(ibuf, '(');
		while (param) {
		    message_write_nstring(ibuf, param->attribute);
		    PUTIBUF(ibuf, ' ');
		    message_write_nstring(ibuf, param->value);
		    if ((param = param->next)!=NULL) {
			PUTIBUF(ibuf, ' ');
		    }
		}
		PUTIBUF(ibuf, ')');
	    }
	    else message_write_nstring(ibuf, (char *)0);
	    PUTIBUF(ibuf, ' ');
	    if (body->disposition) {
		PUTIBUF(ibuf, '(');
		message_write_nstring(ibuf, body->disposition);
		PUTIBUF(ibuf, ' ');
		if ((param = body->disposition_params)!=NULL) {
		    PUTIBUF(ibuf, '(');
		    while (param) {
			message_write_nstring(ibuf, param->attribute);
			PUTIBUF(ibuf, ' ');
			message_write_nstring(ibuf, param->value);
			if ((param = param->next)!=NULL) {
			    PUTIBUF(ibuf, ' ');
			}
		    }
		    PUTIBUF(ibuf, ')');
		}
		else message_write_nstring(ibuf, (char *)0);
		PUTIBUF(ibuf, ')');
	    }
	    else {
		message_write_nstring(ibuf, (char *)0);
	    }
	    PUTIBUF(ibuf, ' ');
	    if ((param = body->language)!=NULL) {
		PUTIBUF(ibuf, '(');
		while (param) {
		    message_write_nstring(ibuf, param->value);
		    if ((param = param->next)!=NULL) {
			PUTIBUF(ibuf, ' ');
		    }
		}
		PUTIBUF(ibuf, ')');
	    }
	    else message_write_nstring(ibuf, (char *)0);
	    PUTIBUF(ibuf, ' ');
	    message_write_nstring(ibuf, body->location);
	}

	PUTIBUF(ibuf, ')');
	return;
    }

    PUTIBUF(ibuf, '(');
    message_write_nstring(ibuf, body->type);
    PUTIBUF(ibuf, ' ');
    message_write_nstring(ibuf, body->subtype);
    PUTIBUF(ibuf, ' ');

    if ((param = body->params)!=NULL) {
	PUTIBUF(ibuf, '(');
	while (param) {
	    message_write_nstring(ibuf, param->attribute);
	    PUTIBUF(ibuf, ' ');
	    message_write_nstring(ibuf, param->value);
	    if ((param = param->next)!=NULL) {
		PUTIBUF(ibuf, ' ');
	    }
	}
	PUTIBUF(ibuf, ')');
    }
    else message_write_nstring(ibuf, (char *)0);
    PUTIBUF(ibuf, ' ');

    message_write_nstring(ibuf, body->id);
    PUTIBUF(ibuf, ' ');
    message_write_nstring(ibuf, body->description);
    PUTIBUF(ibuf, ' ');
    message_write_nstring(ibuf, body->encoding ? body->encoding : "7BIT");
    PUTIBUF(ibuf, ' ');
    message_write_number(ibuf, body->content_size);

    if (strcmp(body->type, "TEXT") == 0) {
	/* Text types get a line count */
	PUTIBUF(ibuf, ' ');
	message_write_number(ibuf, body->content_lines);
    }
    else if (strcmp(body->type, "MESSAGE") == 0
	     && strcmp(body->subtype, "RFC822") == 0) {
	/* Message/rfc822 gets a body_msg */
	PUTIBUF(ibuf, ' ');
	message_write_envelope(ibuf, body->subpart);
	PUTIBUF(ibuf, ' ');
	message_write_body(ibuf, body->subpart, newformat);
	PUTIBUF(ibuf, ' ');
	message_write_number(ibuf, body->content_lines);
    }

    if (newformat) {
	/* Add additional fields for BODYSTRUCTURE */
	PUTIBUF(ibuf, ' ');
	message_write_nstring(ibuf, body->md5);
	PUTIBUF(ibuf, ' ');
	if (body->disposition) {
	    PUTIBUF(ibuf, '(');
	    message_write_nstring(ibuf, body->disposition);
	    PUTIBUF(ibuf, ' ');
	    if ((param = body->disposition_params)!=NULL) {
		PUTIBUF(ibuf, '(');
		while (param) {
		    message_write_nstring(ibuf, param->attribute);
		    PUTIBUF(ibuf, ' ');
		    message_write_nstring(ibuf, param->value);
		    if ((param = param->next)!=NULL) {
			PUTIBUF(ibuf, ' ');
		    }
		}
		PUTIBUF(ibuf, ')');
	    }
	    else message_write_nstring(ibuf, (char *)0);
	    PUTIBUF(ibuf, ')');
	}
	else {
	    message_write_nstring(ibuf, (char *)0);
	}
	PUTIBUF(ibuf, ' ');
	if ((param = body->language)!=NULL) {
	    PUTIBUF(ibuf, '(');
	    while (param) {
		message_write_nstring(ibuf, param->value);
		if ((param = param->next)!=NULL) {
		    PUTIBUF(ibuf, ' ');
		}
	    }
	    PUTIBUF(ibuf, ')');
	}
	else message_write_nstring(ibuf, (char *)0);
	PUTIBUF(ibuf, ' ');
	message_write_nstring(ibuf, body->location);
    }

    PUTIBUF(ibuf, ')');
}

/*
 * Write the address list 'addrlist' to 'ibuf'
 */
static void message_write_address(struct ibuf *ibuf,
				  const struct address *addrlist)
{
    /* If no addresses, write out NIL */
    if (!addrlist) {
	message_write_nstring(ibuf, (char *)0);
	return;
    }

    PUTIBUF(ibuf, '(');

    while (addrlist) {
	PUTIBUF(ibuf, '(');
	message_write_nstring(ibuf, addrlist->name);
	PUTIBUF(ibuf, ' ');
	message_write_nstring(ibuf, addrlist->route);
	PUTIBUF(ibuf, ' ');
	message_write_nstring(ibuf, addrlist->mailbox);
	PUTIBUF(ibuf, ' ');
	message_write_nstring(ibuf, addrlist->domain);
	PUTIBUF(ibuf, ')');
	addrlist = addrlist->next;
    }

    PUTIBUF(ibuf, ')');
}

/*
 * Write the nil-or-string 's' to 'ibuf'
 */
static void message_write_nstring(struct ibuf *ibuf, const char *s)
{
    const char *p;
    int len = 0;

    /* Write null pointer as NIL */
    if (!s) {
	message_ibuf_ensure(ibuf, 3);
	*(ibuf->end)++ = 'N';
	*(ibuf->end)++ = 'I';
	*(ibuf->end)++ = 'L';
	return;
    }

    /* Look for any non-QCHAR characters */
    for (p = s; *p; p++) {
	len++;
	if (*p & 0x80 || *p == '\r' || *p == '\n'
	    || *p == '\"' || *p == '%' || *p == '\\') break;
    }

    if (*p || len >= 1024) {
	/* Write out as literal */
	char buf[100];
	snprintf(buf, sizeof(buf), "{" SIZE_T_FMT "}\r\n", strlen(s));
	message_ibuf_ensure(ibuf, strlen(s)+strlen(buf));
	for (p = buf; *p; p++) *(ibuf->end)++ = *p;
	for (p = s; *p; p++) *(ibuf->end)++ = *p;
    }
    else {
	/* Write out as quoted string */
	message_ibuf_ensure(ibuf, strlen(s)+2);
	*(ibuf->end)++ = '\"';
	for (p = s; *p; p++) *(ibuf->end)++ = *p;
	*(ibuf->end)++ = '\"';
    }
}

/*
 * Write the text 's' to 'ibuf'
 */
static void message_write_text(struct ibuf *ibuf, const char *s)
{
    const char *p;

    message_ibuf_ensure(ibuf, strlen(s));
    for (p = s; *p; p++) *(ibuf->end)++ = *p;
}

/*
 * Write the text 's' to 'ibuf', converting to lower case as we go.
 */
static void message_write_text_lcase(struct ibuf *ibuf, const char *s)
{
    const char *p;

    message_ibuf_ensure(ibuf, strlen(s));
    for (p = s; *p; p++) *(ibuf->end)++ = TOLOWER(*p);
}

/*
 * Write out the IMAP number 'n' to 'ibuf'
 */
static void message_write_number(struct ibuf *ibuf, unsigned n)
{
    char buf[100], *p;

    snprintf(buf, sizeof(buf), "%u", n);

    message_ibuf_ensure(ibuf, strlen(buf));
    for (p = buf; *p; p++) *(ibuf->end)++ = *p;
}

/*
 * Write out the FETCH BODY[section] location/size information to 'ibuf'.
 */
static void message_write_section(struct ibuf *ibuf, const struct body *body)
{
    int part;

    if (strcmp(body->type, "MESSAGE") == 0
	&& strcmp(body->subtype, "RFC822") == 0) {
	if (body->subpart->numparts) {
	    /*
	     * Part 0 of a message/rfc822 is the message header/text.
	     * Nested parts of a message/rfc822 containing a multipart
	     * are the sub-parts of the multipart.
	     */
	    message_write_bit32(ibuf, body->subpart->numparts+1);
	    message_write_bit32(ibuf, body->subpart->header_offset);
	    message_write_bit32(ibuf, body->subpart->header_size);
	    message_write_bit32(ibuf, body->subpart->content_offset);
	    message_write_bit32(ibuf, body->subpart->content_size);
	    message_write_bit32(ibuf, (-1<<16)|ENCODING_NONE);
	    for (part = 0; part < body->subpart->numparts; part++) {
		message_write_bit32(ibuf, body->subpart->subpart[part].header_offset);
		message_write_bit32(ibuf, body->subpart->subpart[part].header_size);
		message_write_bit32(ibuf, body->subpart->subpart[part].content_offset);
		if (body->subpart->subpart[part].numparts == 0 &&
		    strcmp(body->subpart->subpart[part].type, "MULTIPART") == 0) {
		    /* Treat 0-part multipart as 0-length text */
		    message_write_bit32(ibuf, 0);
		}
		else {
		    message_write_bit32(ibuf, body->subpart->subpart[part].content_size);
		}
		message_write_charset(ibuf, &body->subpart->subpart[part]);
	    }
	    for (part = 0; part < body->subpart->numparts; part++) {
		message_write_section(ibuf, &body->subpart->subpart[part]);
	    }
	}
	else {
	    /*
	     * Part 0 of a message/rfc822 is the message header/text.
	     * Part 1 of a message/rfc822 containing a non-multipart
	     * is the message body.
	     */
	    message_write_bit32(ibuf, 2);
	    message_write_bit32(ibuf, body->subpart->header_offset);
	    message_write_bit32(ibuf, body->subpart->header_size);
	    message_write_bit32(ibuf, body->subpart->content_offset);
	    message_write_bit32(ibuf, body->subpart->content_size);
	    message_write_bit32(ibuf, (-1<<16)|ENCODING_NONE);
	    message_write_bit32(ibuf, body->subpart->header_offset);
	    message_write_bit32(ibuf, body->subpart->header_size);
	    message_write_bit32(ibuf, body->subpart->content_offset);
	    if (strcmp(body->subpart->type, "MULTIPART") == 0) {
		/* Treat 0-part multipart as 0-length text */
		message_write_bit32(ibuf, 0);
		message_write_bit32(ibuf, (-1<<16)|ENCODING_NONE);
	    }
	    else {
		message_write_bit32(ibuf, body->subpart->content_size);
		message_write_charset(ibuf, body->subpart);
	    }
	    message_write_section(ibuf, body->subpart);
	}
    }
    else if (body->numparts) {
	/*
	 * Cannot fetch part 0 of a multipart.
	 * Nested parts of a multipart are the sub-parts.
	 */
	message_write_bit32(ibuf, body->numparts+1);	
	message_write_bit32(ibuf, 0);
	message_write_bit32(ibuf, -1);
	message_write_bit32(ibuf, 0);
	message_write_bit32(ibuf, -1);
	message_write_bit32(ibuf, (-1<<16)|ENCODING_NONE);
	for (part = 0; part < body->numparts; part++) {
	    message_write_bit32(ibuf, body->subpart[part].header_offset);
	    message_write_bit32(ibuf, body->subpart[part].header_size);
	    message_write_bit32(ibuf, body->subpart[part].content_offset);
	    if (body->subpart[part].numparts == 0 &&
		strcmp(body->subpart[part].type, "MULTIPART") == 0) {
		/* Treat 0-part multipart as 0-length text */
		message_write_bit32(ibuf, 0);
		message_write_bit32(ibuf, (-1<<16)|ENCODING_NONE);
	    }
	    else {
		message_write_bit32(ibuf, body->subpart[part].content_size);
		message_write_charset(ibuf, &body->subpart[part]);
	    }
	}
	for (part = 0; part < body->numparts; part++) {
	    message_write_section(ibuf, &body->subpart[part]);
	}
    }
    else {
	/*
	 * Leaf section--no part 0 or nested parts
	 */
	message_write_bit32(ibuf, 0);
    }
}

/*
 * Write the 32-bit charset/encoding value for section 'body' to 'ibuf'
 */
static void message_write_charset(struct ibuf *ibuf, const struct body *body)
{
    int encoding, charset;

    message_parse_charset(body, &encoding, &charset);

    message_write_bit32(ibuf, (charset<<16)|encoding);
}

/*
 * Write the 32-bit integer quantitiy 'val' to 'ibuf'
 */
static void message_write_bit32(struct ibuf *ibuf, bit32 val)
{
    bit32 buf;
    unsigned i;
    char *p = (char *)&buf;
    
    message_ibuf_ensure(ibuf, sizeof(bit32));
    buf = htonl(val);

    for (i=0; i < sizeof(bit32); i++) {
	*(ibuf->end)++ = *p++;
    }
}

/*
 * Unparse the address list 'addrlist' to 'ibuf'
 */
static void message_write_searchaddr(struct ibuf *ibuf,
				     const struct address *addrlist)
{
    int prevaddr = 0;
    char* tmp;

    while (addrlist) {

	/* Handle RFC-822 group addresses */
	if (!addrlist->domain) {
	    if (addrlist->mailbox) {
		if (prevaddr) PUTIBUF(ibuf, ',');
		
		tmp = charset_decode_mimeheader(addrlist->mailbox);
		message_write_text(ibuf, tmp);
		free(tmp);
		tmp = NULL;
		PUTIBUF(ibuf, ':');
	
		/* Suppress a trailing comma */
		prevaddr = 0;
	    }
	    else {
		PUTIBUF(ibuf, ';');
		prevaddr = 1;
	    }
	}
	else {
	    if (prevaddr) PUTIBUF(ibuf, ',');

	    if (addrlist->name) {
		tmp = charset_decode_mimeheader(addrlist->name);
		message_write_text(ibuf, tmp);
		free(tmp); tmp = NULL;
		PUTIBUF(ibuf, ' ');
	    }

	    PUTIBUF(ibuf, '<');
	    if (addrlist->route) {
		message_write_text_lcase(ibuf, addrlist->route);
		PUTIBUF(ibuf, ':');
	    }

	    message_write_text_lcase(ibuf, addrlist->mailbox);
	    PUTIBUF(ibuf, '@');

	    message_write_text_lcase(ibuf, addrlist->domain);
	    PUTIBUF(ibuf, '>');
	    prevaddr = 1;
	}

	addrlist = addrlist->next;
    }
}

/*
 * Initialize 'ibuf'
 */
#define IBUFGROWSIZE 1000
static void message_ibuf_init(struct ibuf *ibuf)
{
    char *s = xmalloc(IBUFGROWSIZE);

    ibuf->start = ibuf->end = s + sizeof(bit32);
    ibuf->last = ibuf->start + IBUFGROWSIZE - sizeof(bit32);
}

static void message_ibuf_copy(struct ibuf *dest, const struct ibuf *src)
{
    unsigned len = src->end - src->start;
    message_ibuf_ensure(dest, len);
    strncpy(dest->end, src->start, len);
    dest->end += len;
}

/*
 * Ensure 'ibuf' has enough free space to append 'len' bytes.
 */
static int message_ibuf_ensure(struct ibuf *ibuf, unsigned len)
{
    char *s;
    int size;

    if ((unsigned) (ibuf->last - ibuf->end) >= len) return 0;
    if (len < IBUFGROWSIZE) len = IBUFGROWSIZE;

    s = ibuf->start - sizeof(bit32);
    size = len + (ibuf->last - ibuf->start);
    s = xrealloc(s, size + sizeof(bit32));
    s += sizeof(bit32);
    ibuf->end = (ibuf->end - ibuf->start) + s;
    ibuf->start = s;
    ibuf->last = s + size;

    return 1;
}

/*
 * Copy the value in to the cache iov
 */
static void message_ibuf_pad(struct ibuf *ibuf)
{
    /* make sure we can write these things out, ho hum */
    message_ibuf_ensure(ibuf, 3);
    ibuf->end[0] = '\0';
    ibuf->end[1] = '\0';
    ibuf->end[2] = '\0';
}

/*
 * Free the space used by 'ibuf'
 */
static void message_ibuf_free(struct ibuf *ibuf)
{
    free(ibuf->start - sizeof(bit32));
}

/*
 * Free the parsed body-part 'body'
 */
void message_free_body(struct body *body)
{
    struct param *param, *nextparam;
    int part;

    if (body->type) {
	free(body->type);
	free(body->subtype);
	for (param = body->params; param; param = nextparam) {
	    nextparam = param->next;
	    free(param->attribute);
	    free(param->value);
	    free(param);
	}
    }
    if (body->id) free(body->id);
    if (body->description) free(body->description);
    if (body->encoding) free(body->encoding);
    if (body->md5) free(body->md5);
    if (body->disposition) {
	free(body->disposition);
	for (param = body->disposition_params; param; param = nextparam) {
	    nextparam = param->next;
	    free(param->attribute);
	    free(param->value);
	    free(param);
	}
    }
    for (param = body->language; param; param = nextparam) {
	nextparam = param->next;
	free(param->value);
	free(param);
    }
    if (body->location) free(body->location);
    if (body->date) free(body->date);
    if (body->subject) free(body->subject);
    if (body->from) parseaddr_free(body->from);
    if (body->sender) parseaddr_free(body->sender);
    if (body->reply_to) parseaddr_free(body->reply_to);
    if (body->to) parseaddr_free(body->to);
    if (body->cc) parseaddr_free(body->cc);
    if (body->bcc) parseaddr_free(body->bcc);
    if (body->in_reply_to) free(body->in_reply_to);
    if (body->message_id) free(body->message_id);
    if (body->references) free(body->references);
    if (body->received_date) free(body->received_date);

    if (body->subpart) {
	if (body->numparts) {
	    for (part=0; part < body->numparts; part++) {
		message_free_body(&body->subpart[part]);
	    }
	}
	else {
	    message_free_body(body->subpart);
	}
	free(body->subpart);
    }

    if (body->cacheheaders.start) {
	message_ibuf_free(&body->cacheheaders);
    }

    if (body->decoded_body) free(body->decoded_body);
}

/*
 * Parse a cached envelope into individual tokens
 *
 * When inside a list (ncom > 0), we parse the individual tokens but don't
 * isolate them -- we return the entire list as a single token.
 */
void parse_cached_envelope(char *env, char *tokens[], int tokens_size)
{
    char *c;
    int i = 0, ncom = 0, len;

    c = env;
    while (*c != '\0') {
	switch (*c) {
	case ' ':			/* end of token */
	    if (!ncom) *c = '\0';	/* mark end of token */
	    c++;
	    break;
	case 'N':			/* "NIL" */
	case 'n':
	    if (!ncom) {
		if(i>=tokens_size) break;
		tokens[i++] = NULL;	/* empty token */
	    }
	    c += 3;			/* skip "NIL" */
	    break;
	case '"':			/* quoted string */
	    c++;			/* skip open quote */
	    if (!ncom) {
		if(i>=tokens_size) break;
		tokens[i++] = c;	/* start of string */
	    }
	    while (*c && *c != '"') {		/* find close quote */
		if (*c == '\\') c++;	/* skip quoted-specials */
		if (*c) c++;
	    }
	    if (*c) {
		if (!ncom) *c = '\0';	/* end of string */
		c++;			/* skip close quote */
	    }
	    break;
	case '{':			/* literal */
	    c++;			/* skip open brace */
	    len = 0;			/* determine length of literal */
	    while (cyrus_isdigit((int) *c)) {
		len = len*10 + *c - '0';
		c++;
	    }
	    c += 3;			/* skip close brace & CRLF */
	    if (!ncom){
		if(i>=tokens_size) break;
		tokens[i++] = c;	/* start of literal */
	    }
	    c += len;			/* skip literal */
	    break;
	case '(':			/* start of address */
	    c++;			/* skip open paren */
	    if (!ncom) {
		if(i>=tokens_size) break;
		tokens[i++] = c;	/* start of address list */
	    }
	    ncom++;			/* new open - inc counter */
	    break;
	case ')':			/* end of address */
	    c++;			/* skip close paren */
	    if (ncom) {			/* paranoia */
		ncom--;			/* close - dec counter */
		if (!ncom)		/* all open paren are closed */
		    *(c-1) = '\0';	/* end of list - trim close paren */
	    }
	    break;
	default:
	    /* yikes! unparsed junk, just skip it */
	    c++;
	    break;
	}
    }
}


/*
 * Generate a conversation id from the given message.
 * The conversation id is defined as the first 64b of
 * the SHA1 of the message, except that an all-zero
 * conversation id is not valid.
 */
static conversation_id_t generate_conversation_id(const struct body *body)
{
    conversation_id_t cid = 0;
    size_t i;

    assert(body->guid.status == GUID_NONNULL);

    for (i = 0 ; i < sizeof(cid) ; i++) {
	cid <<= 8;
	cid |= body->guid.value[i];
    }

    /*
     * We carefully avoid returning NULLCONVERSATION as
     * a new cid, as that would confuse matters no end.
     */
    if (cid == NULLCONVERSATION)
	cid = 1;

    return cid;
}

/*
 * Update the conversations database for the given
 * mailbox, to account for the given new message.
 */
int message_update_conversations(struct conversations_state *state,
			         struct index_record *record,
			         const struct body *body)
{
    char *hdrs[3];
    /* TODO: need an expanding array class here */
    struct {
	char *msgid;
	conversation_id_t cid;
    } *found = NULL;
    int nfound = 0;
#define ALLOCINCREMENT 16
    conversation_id_t newcid = record->cid;
    int i;
    int j;
    int r = 0;
    char *msgid;

    /*
     * Gather all the msgids mentioned in the message, starting with
     * the oldest message in the References: header, then any mesgids
     * mentioned in the In-Reply-To: header, and finally the message's
     * own Message-Id:.  In general this will result in duplicates (a
     * correct References: header will contain as its last entry the
     * msgid in In-Reply-To:), so we weed those out before proceeding
     * to the database.
     */
    hdrs[0] = body->references;
    hdrs[1] = body->in_reply_to;
    hdrs[2] = body->message_id;
    for (i = 0 ; i < 3 ; i++) {
continue2:
	while ((msgid = find_msgid(hdrs[i], &hdrs[i])) != NULL) {

	    /*
	     * The issue of case sensitivity of msgids is curious.
	     * RFC2822 seems to imply they're case-insensitive,
	     * without explicitly stating so.  So here we punt
	     * on that being the case.
	     *
	     * Note that the THREAD command elsewhere in Cyrus
	     * assumes otherwise.
	     */
	    msgid = lcase(msgid);

	    /* check for duplicates.  O(N^2), yuck */
	    for (j = 0 ; j < nfound ; j++) {
		if (!strcmp(msgid, found[j].msgid)) {
		    free(msgid);
		    goto continue2;
		}
	    }

	    /* it's unique, add it */

	    if (nfound % ALLOCINCREMENT == 0) {
		found = xrealloc(found,
			    (nfound+ALLOCINCREMENT) * sizeof(*found));
	    }

	    found[nfound].msgid = msgid;
	    found[nfound].cid = NULLCONVERSATION;
	    nfound++;
	}
    }

    /*
     * For each unique message-id, lookup the conversations database
     * to work out which conversation id that message belongs to.
     */
    for (i = 0 ; i < nfound ; i++) {
	r = conversations_get_msgid(state, found[i].msgid, &found[i].cid);
	if (r)
	    goto out;
	/* Use the MAX of any CIDs found - as NULLCONVERSATION is
	 * numerically zero this will be the only non-NULL CID or
	 * the MAX of two or more non-NULL CIDs */
	newcid = (newcid > found[i].cid ? newcid : found[i].cid);
    }

    if (newcid == NULLCONVERSATION)
	newcid = generate_conversation_id(body);

    /*
     * Update the database to add records for all the message-ids
     * not already mentioned.  Note that we take care to avoid
     * setting those which are already set, because that would be
     * wasteful and it would also change the record's timestamp,
     * which would stuff up pruning of the database.
     */
    for (i = 0 ; i < nfound ; i++) {
	if (found[i].cid == newcid)
	    continue;

	if (found[i].cid != NULLCONVERSATION) {
	    /* CIDs clashed */
	    r = mailbox_rename_cid(state, found[i].cid, newcid);
	    if (r)
		goto out;
	}

	r = conversations_set_msgid(state, found[i].msgid, newcid);
	if (r)
	    goto out;
    }

    record->cid = newcid;

out:
    for (i = 0 ; i < nfound ; i++)
	free(found[i].msgid);
    free(found);
    return r;
}

int message_update_conversations_file(struct conversations_state *state,
				      struct index_record *record,
				      const char *fname)
{
    struct body *body = NULL;
    FILE *fp;
    int r;

    fp = fopen(fname, "r");
    if (fp == NULL)
	return IMAP_IOERROR;

    r = message_parse_file(fp, NULL, NULL, &body);
    fclose(fp);
    if (r)
	return r;

    r = message_update_conversations(state, record, body);

    message_free_body(body);

    return r;
}


static char *parse_nstring(char **str)
{
    char *cp = *str, *val;

    if (*cp == '"') { /* quoted string */
	val = ++cp; /* skip " */
	do {
	    cp = strchr(cp, '"');
	    if (!cp) return NULL; /* whole thing is broken */
	} while (*(cp-1) == '\\'); /* skip escaped " */
	*cp++ = '\0';
    }
    else { /* NIL */
	val = NULL;
	cp += 3;
    }

    *str = cp;
    return val;
}

void message_parse_env_address(char *str, struct address *addr)
{
    str++; /* skip ( */
    addr->name = parse_nstring(&str);
    str++; /* skip SP */
    addr->route = parse_nstring(&str);
    str++; /* skip SP */
    addr->mailbox = parse_nstring(&str);
    str++; /* skip SP */
    addr->domain = parse_nstring(&str);
}
