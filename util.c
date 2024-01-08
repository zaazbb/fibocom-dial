#include <sys/time.h>

#include "QMIThread.h"

#if defined(__STDC__)
#include <stdarg.h>
#define __V(x) x
#else
#include <varargs.h>
#define __V(x) (va_alist) va_dcl
#define const
#define volatile
#endif

#include <syslog.h>

#define is_bigendian() ((*(char *)&i) == 0)
FILE *logfilefp = NULL;
static pthread_mutex_t printfMutex = PTHREAD_MUTEX_INITIALIZER;
static char line[1024];
const int i = 1;

// defined in atchannel.c
static void setTimespecRelative(struct timespec *p_ts, long long msec)
{
    struct timeval tv;

    gettimeofday(&tv, (struct timezone *)NULL);

    /* what's really funny about this is that I know
       pthread_cond_timedwait just turns around and makes this
       a relative time again */
    p_ts->tv_sec = tv.tv_sec + (msec / 1000);
    p_ts->tv_nsec = (tv.tv_usec + (msec % 1000) * 1000L) * 1000L;
}

int pthread_cond_timeout_np(pthread_cond_t *cond, pthread_mutex_t *mutex,
			    unsigned msecs)
{
    if (msecs != 0) {
	struct timespec ts;
	setTimespecRelative(&ts, msecs);
	return pthread_cond_timedwait(cond, mutex, &ts);
    } else {
	return pthread_cond_wait(cond, mutex);
    }
}

static const char *get_time(void)
{
    static char time_buf[50];
    struct timeval tv;
    time_t time;
    suseconds_t millitm;
    struct tm *ti;

    gettimeofday(&tv, NULL);

    time = tv.tv_sec;
    millitm = (tv.tv_usec + 500) / 1000;

    if (millitm == 1000) {
	++time;
	millitm = 0;
    }

    ti = localtime(&time);
    sprintf(time_buf, "[%02d-%02d_%02d:%02d:%02d:%03d]", ti->tm_mon + 1,
	    ti->tm_mday, ti->tm_hour, ti->tm_min, ti->tm_sec, (int)millitm);
    return time_buf;
}

void dbg_time(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    pthread_mutex_lock(&printfMutex);

    snprintf(line, sizeof(line), "%s ", get_time());

    vsnprintf(line + strlen(line), sizeof(line) - strlen(line), fmt, args);
    fprintf(stdout, "%s\n", line);

    if (logfilefp) {
	fprintf(logfilefp, "%s\n", line);
    }
    fflush(logfilefp);
    pthread_mutex_unlock(&printfMutex);
}

USHORT le16_to_cpu(USHORT v16)
{
    USHORT tmp = v16;
    if (is_bigendian()) {
	unsigned char *s = (unsigned char *)(&v16);
	unsigned char *d = (unsigned char *)(&tmp);
	d[0] = s[1];
	d[1] = s[0];
    }
    return tmp;
}

UINT le32_to_cpu(UINT v32)
{
    UINT tmp = v32;
    if (is_bigendian()) {
	unsigned char *s = (unsigned char *)(&v32);
	unsigned char *d = (unsigned char *)(&tmp);
	d[0] = s[3];
	d[1] = s[2];
	d[2] = s[1];
	d[3] = s[0];
    }
    return tmp;
}

USHORT cpu_to_le16(USHORT v16)
{
    USHORT tmp = v16;
    if (is_bigendian()) {
	unsigned char *s = (unsigned char *)(&v16);
	unsigned char *d = (unsigned char *)(&tmp);
	d[0] = s[1];
	d[1] = s[0];
    }
    return tmp;
}

UINT cpu_to_le32(UINT v32)
{
    UINT tmp = v32;
    if (is_bigendian()) {
	unsigned char *s = (unsigned char *)(&v32);
	unsigned char *d = (unsigned char *)(&tmp);
	d[0] = s[3];
	d[1] = s[2];
	d[2] = s[1];
	d[3] = s[0];
    }
    return tmp;
}

void update_resolv_conf(int iptype, const char *ifname, const char *dns1, const char *dns2) {
    const char *dns_file = "/etc/resolv.conf";
    FILE *dns_fp;
    char dns_line[256];
    #define MAX_DNS 16
    char *dns_info[MAX_DNS];
    char dns_tag[64];
    int dns_match = 0;
    int i;

    snprintf(dns_tag, sizeof(dns_tag), "# IPV%d %s", iptype, ifname);

    for (i = 0; i < MAX_DNS; i++)
        dns_info[i] = NULL;
    
    dns_fp = fopen(dns_file, "r");
    if (dns_fp) {
        i = 0;    
        dns_line[sizeof(dns_line)-1] = '\0';
        
        while((fgets(dns_line, sizeof(dns_line)-1, dns_fp)) != NULL) {
            if ((strlen(dns_line) > 1) && (dns_line[strlen(dns_line) - 1] == '\n'))
                dns_line[strlen(dns_line) - 1] = '\0';
            //dbg_time("%s", dns_line);
            if (strstr(dns_line, dns_tag)) {
                dns_match++;
                continue;
            }
            dns_info[i++] = strdup(dns_line);
            if (i == MAX_DNS)
                break;
        }

        fclose(dns_fp);
    }
    else if (errno != ENOENT) {
        dbg_time("fopen %s fail, errno:%d (%s)", dns_file, errno, strerror(errno));
        return;
    }
    
    if (dns1 == NULL && dns_match == 0)
        return;

    dns_fp = fopen(dns_file, "w");
    if (dns_fp) {
        if (dns1)
            fprintf(dns_fp, "nameserver %s %s\n", dns1, dns_tag);
        if (dns2)
            fprintf(dns_fp, "nameserver %s %s\n", dns2, dns_tag);
        
        for (i = 0; i < MAX_DNS && dns_info[i]; i++)
            fprintf(dns_fp, "%s\n", dns_info[i]);
        fclose(dns_fp);
    }
    else {
        dbg_time("fopen %s fail, errno:%d (%s)", dns_file, errno, strerror(errno));
    }

    for (i = 0; i < MAX_DNS && dns_info[i]; i++)
        free(dns_info[i]);
}

