/* cunit.h - wrapper for CUnit assert macros
 *
 * Copyright (c) 1994-2010 Carnegie Mellon University.  All rights reserved.
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
 */

#ifndef INCLUDED_CUNIT_H
#define INCLUDED_CUNIT_H

#include <stdio.h>
#include <stdarg.h>
#include <CUnit/CUnit.h>
#include "cunit-syslog.h"

extern int verbose;

/*
 * The standard CUnit assertion *EQUAL* macros have a flaw: they do
 * not report the actual values of the 'actual' and 'expected' values,
 * which makes it rather hard to see why an assertion failed.  So we
 * replace the macros with improved ones, keeping the same API.
 */
extern CU_BOOL CU_assertFormatImplementation(CU_BOOL bValue, unsigned int uiLine,
					     char strFile[], char strFunction[],
					     CU_BOOL bFatal,
					     char strConditionFormat[], ...);
extern void __cunit_wrap_test(const char *name, void (*fn)(void));
extern int __cunit_wrap_fixture(const char *name, int (*fn)(void));

#undef CU_ASSERT_EQUAL
#define CU_ASSERT_EQUAL(actual,expected) \
  { long long _a = (actual), _e = (expected); \
    CU_assertFormatImplementation((_a == _e), __LINE__, \
     __FILE__, "", CU_FALSE, \
    "CU_ASSERT_EQUAL(" #actual "=%lld," #expected "=%lld)", _a, _e); }

#undef CU_ASSERT_EQUAL_FATAL
#define CU_ASSERT_EQUAL_FATAL(actual,expected) \
  { long long _a = (actual), _e = (expected); \
    CU_assertFormatImplementation((_a == _e), __LINE__, \
     __FILE__, "", CU_TRUE, \
    "CU_ASSERT_EQUAL_FATAL(" #actual "=%lld," #expected "=%lld)", _a, _e); }

#undef CU_ASSERT_NOT_EQUAL
#define CU_ASSERT_NOT_EQUAL(actual,expected) \
  { long long _a = (actual), _e = (expected); \
    CU_assertFormatImplementation((_a != _e), __LINE__, \
     __FILE__, "", CU_FALSE, \
    "CU_ASSERT_NOT_EQUAL(" #actual "=%lld," #expected "=%lld)", _a, _e); }

#undef CU_ASSERT_NOT_EQUAL_FATAL
#define CU_ASSERT_NOT_EQUAL_FATAL(actual,expected) \
  { long long _a = (actual), _e = (expected); \
    CU_assertFormatImplementation((_a != _e), __LINE__, \
     __FILE__, "", CU_TRUE, \
    "CU_ASSERT_NOT_EQUAL_FATAL(" #actual "=%lld," #expected "=%lld)", _a, _e); }



#undef CU_ASSERT_PTR_EQUAL
#define CU_ASSERT_PTR_EQUAL(actual,expected) \
  { void *_a = (actual), *_e = (expected); \
    CU_assertFormatImplementation((_a == _e), __LINE__, \
     __FILE__, "", CU_FALSE, \
    "CU_ASSERT_PTR_EQUAL(" #actual "=%p," #expected "=%p)", _a, _e); }

#undef CU_ASSERT_PTR_EQUAL_FATAL
#define CU_ASSERT_PTR_EQUAL_FATAL(actual,expected) \
  { void *_a = (actual), *_e = (expected); \
    CU_assertFormatImplementation((_a == _e), __LINE__, \
     __FILE__, "", CU_TRUE, \
    "CU_ASSERT_PTR_EQUAL_FATAL(" #actual "=%p," #expected "=%p)", _a, _e); }

#undef CU_ASSERT_PTR_NOT_EQUAL
#define CU_ASSERT_PTR_NOT_EQUAL(actual,expected) \
  { void *_a = (actual), *_e = (expected); \
    CU_assertFormatImplementation((_a != _e), __LINE__, \
     __FILE__, "", CU_FALSE, \
    "CU_ASSERT_PTR_NOT_EQUAL(" #actual "=%p," #expected "=%p)", _a, _e); }

#undef CU_ASSERT_PTR_NOT_EQUAL_FATAL
#define CU_ASSERT_PTR_NOT_EQUAL_FATAL(actual,expected) \
  { void *_a = (actual), *_e = (expected); \
    CU_assertFormatImplementation((_a != _e), __LINE__, \
     __FILE__, "", CU_TRUE, \
    "CU_ASSERT_PTR_NOT_EQUAL_FATAL(" #actual "=%p," #expected "=%p)", _a, _e); }


#undef CU_ASSERT_STRING_EQUAL
#define CU_ASSERT_STRING_EQUAL(actual,expected) \
  { const char *_a = (actual), *_e = (expected); \
    CU_assertFormatImplementation(!strcmp(_a?_a:"",_e?_e:""), __LINE__, \
     __FILE__, "", CU_FALSE, \
    "CU_ASSERT_STRING_EQUAL(" #actual "=\"%s\"," #expected "=\"%s\")", _a, _e); }

#undef CU_ASSERT_STRING_EQUAL_FATAL
#define CU_ASSERT_STRING_EQUAL_FATAL(actual,expected) \
  { const char *_a = (actual), *_e = (expected); \
    CU_assertFormatImplementation(!strcmp(_a?_a:"",_e?_e:""), __LINE__, \
     __FILE__, "", CU_TRUE, \
    "CU_ASSERT_STRING_EQUAL_FATAL(" #actual "=\"%s\"," #expected "=\"%s\")", _a, _e); }

#undef CU_ASSERT_STRING_NOT_EQUAL
#define CU_ASSERT_STRING_NOT_EQUAL(actual,expected) \
  { const char *_a = (actual), *_e = (expected); \
    CU_assertFormatImplementation(!!strcmp(_a?_a:"",_e?_e:""), __LINE__, \
     __FILE__, "", CU_FALSE, \
    "CU_ASSERT_STRING_NOT_EQUAL(" #actual "=\"%s\"," #expected "=\"%s\")", _a, _e); }

#undef CU_ASSERT_STRING_NOT_EQUAL_FATAL
#define CU_ASSERT_STRING_NOT_EQUAL_FATAL(actual,expected) \
  { const char *_a = (actual), *_e = (expected); \
    CU_assertFormatImplementation(!!strcmp(_a?_a:"",_e?_e:""), __LINE__, \
     __FILE__, "", CU_TRUE, \
    "CU_ASSERT_STRING_NOT_EQUAL_FATAL(" #actual "=\"%s\"," #expected "=\"%s\")", _a, _e); }

#define CU_SYSLOG_MATCH(re) \
    CU_syslogMatchBegin((re), __FILE__, __LINE__)
#define CU_ASSERT_SYSLOG(match, expected) \
  { const char *_s = NULL; unsigned int _e = (expected), \
    _a = CU_syslogMatchEnd((match), &_s); \
    CU_assertFormatImplementation((_a == _e), __LINE__, \
     __FILE__, "", CU_FALSE, \
    "CU_ASSERT_SYSLOG(/%s/=%u, " #expected "=%u)", _s, _a, _e); }
#define CU_ASSERT_SYSLOG_FATAL(match, expected) \
  { const char *_s = NULL; unsigned int _e = (expected), \
    _a = CU_syslogMatchEnd((match), &_s); \
    CU_assertFormatImplementation((_a == _e), __LINE__, \
     __FILE__, "", CU_TRUE, \
    "CU_ASSERT_SYSLOG_FATAL(/%s/=%u, " #expected "=%u)", _s, _a, _e); }

/* for parametrised tests */

#define CUNIT_PARAM(x)	    (x)

struct cunit_param
{
    /* initialisation state */
    const char *name;
    char **variable;
    /* iteration state */
    int nvalues;
    char **values;
    int idx;
    char *freeme1;
};
#define __CUNIT_DECLARE_PARAM(nm) \
    { #nm, &nm, 0, NULL, 0, NULL }
#define __CUNIT_LAST_PARAM \
    { NULL, NULL, 0, NULL, 0, NULL }

extern void __cunit_params_begin(struct cunit_param *);
extern int __cunit_params_next(struct cunit_param *);
extern void __cunit_params_end(struct cunit_param *);

#endif /* INCLUDED_CUNIT_H */
