/*
 * autotime.h
 *
 * The code here tries its best to provide access to struct tm and the 
 * timezone name.
 *
 * In addition to including time.h (and sys/time.h), autotime.h defines the 
 * macro tm_zone() that may be used to get the timezone name given a 
 * struct tm pointer.
 *
 * Requires the following configure.in macros:
 * AC_CHECK_HEADERS(sys/time.h)
 * AC_HEADER_TIME
 * AC_STRUCT_TM
 * AC_STRUCT_TIMEZONE
 *
 * Also see:
 * http://www.lns.cornell.edu/public/COMP/info/autoconf/autoconf_4.html#SEC32
 */

#ifndef _AUTOTIME_H_
#define _AUTOTIME_H_

#include "config.h"

#if TM_IN_SYS_TIME          /* struct tm is not in time.h ... */
  #if HAVE_SYS_TIME_H
    #if TIME_WITH_SYS_TIME
      #include <sys/time.h>
      #include <time.h>
    #else
      #include <sys/time.h> /* Supposedly includes time.h */
    #endif
  #else
    #include <time.h>       /* No struct tm in time.h and no sys/time.h ??? */
  #endif
#else
  #include <time.h>
#endif

#if HAVE_TM_ZONE
  #define tm_zone(tm) (tm->tm_zone)
#elif HAVE_TZNAME
  #define tm_zone(tm) (tzname[tm->tm_isdst])
#else
  #ifndef tzname            /* Don't step on macro (SGI) */
  extern char* tzname[];    /* RS6000 doesn't like **tzname */ 
  #endif
  #define tm_zone(tm) (tzname[tm->tm_isdst])
#endif

#endif /* _AUTOTIME_H_ */

