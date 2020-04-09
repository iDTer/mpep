


#include <unistd.h>
#include <assert.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/user.h>

#define __USE_XOPEN_EXTENDED
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netdb.h>
#include <getopt.h>
#include <linux/netfilter.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <sys/poll.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <syslog.h>

#include <sys/time.h>

/*
 * Data structure to fill with packet headers when we
 * get a new syn:
 *
 * struct ipv4_packet
 *      iph : ip header for the packet
 *      tcph: tcp header for the segment
 *
 */
struct ipv4_packet {
	struct iphdr iph;
	struct tcphdr tcph;
};

static int DEBUG = 0;
static int background = 0;
static int fastopen = 0;
static int gcc_interval = PEP_GCC_INTERVAL;
static char pepsal_ip_addr[20] = "0.0.0.0";

/*
 * The main aim of this structure is to reduce search time
 * of pep_proxy instance corresponding to the returned by poll()
 * file descriptor. Typically to find pep_proxy by one of its FDs
 * takes linear time(because pep_proxys are arranged into one list),
 * but this structure reduce search time to O(1).
 * pollfds is an array of file descriptors and events used by poll.
 * pdescrs is an array of pointers to corresponding pep_endpoint entries.
 * Each Ith FD corresponds to Ith pep_proxy. Both array have the same
 * size equal to num_pollfds items.
 */
static struct {
	struct pollfd           *pollfds;
	struct pep_endpoint		**endpoints;
	int                     num_pollfds;
} poll_resources;


struct pep_logger {
	FILE *file;
	timer_t timer;
	char *filename;
};

/*
 * 轮询机制
 */
static struct pep_queue active_queue, ready_queue;
static struct pep_logger logger;

static pthread_t listener;
static pthread_t poller;
static pthread_t timer_sch;
static pthread_t *workers = NULL;

// DEBUG
#define pep_error(fmt, args...)                       \
    syslog(LOG_ERR, "%s():%d: " fmt " (errno %d)",    \
           __FUNCTION__, __LINE__, ##args, errno);    \
    __pep_error(__FUNCTION__, __LINE__, fmt, ##args)  

#define pep_warning(fmt, args...)                     \
    syslog(LOG_WARNING, "%s():%d: " fmt,              \
           __FUNCTION__, __LINE__, ##args);           \
    __pep_warning(__FUNCTION__, __LINE__, fmt, ##args)

#define PEP_DEBUG(fmt, args...)                       \
    if (DEBUG) {                                      \
        fprintf(stderr, "[DEBUG] %s(): " fmt "\n",    \
                __FUNCTION__, ##args);                \
        syslog(LOG_DEBUG, "%s(): " fmt, __FUNCTION__, \
              ##args);                                \
    }

#define PEP_DEBUG_DP(proxy, fmt, args...)                           \
    if (DEBUG) {                                                    \
        char __buf[17];                                             \
        toip(__buf, (proxy)->src.addr);                             \
        fprintf(stderr, "[DEBUG] %s(): {%s:%d} " fmt "\n",          \
                __FUNCTION__, __buf, (proxy)->src.port, ##args);    \
        syslog(LOG_DEBUG, "%s(): {%s:%d} " fmt, __FUNCTION__,       \
               __buf, (proxy)->src.port, ##args);                   \
    }

static void __pep_error(const char *function, int line, const char *fmt, ...)
{
    va_list ap;
    char buf[PEP_ERRBUF_SZ];
    int err = errno;
    size_t len;

    va_start(ap, fmt);

    len = snprintf(buf, PEP_ERRBUF_SZ, "[ERROR]: ");
    len += vsnprintf(buf + len, PEP_ERRBUF_SZ - len, fmt, ap);
    if (err && (PEP_ERRBUF_SZ - len) > 1) {
        snprintf(buf + len, PEP_ERRBUF_SZ - len,
                 "\n      ERRNO: [%s:%d]", strerror(err), err);
    }

    fprintf(stderr, "%s\n         AT: %s:%d\n", buf, function, line);
    va_end(ap);
    closelog();
    exit(EXIT_FAILURE);
}

static void __pep_warning(const char *function, int line, const char *fmt, ...)
{
    va_list ap;
    char buf[PEP_ERRBUF_SZ];
    size_t len;

    va_start(ap, fmt);
    len = snprintf(buf, PEP_ERRBUF_SZ, "[WARNING]: ");
    if (PEP_ERRBUF_SZ - len > 1) {
        len += vsnprintf(buf + len, PEP_ERRBUF_SZ - len, fmt, ap);
    }

    fprintf(stderr, "%s\n       AT: %s:%d\n", buf, function, line);
    va_end(ap);
}

static void usage(char *name)
{
    fprintf(stderr,"Usage: %s [-V] [-h] [-v] [-d] [-f]"
            " [-a address] [-p port]"
            " [-c max_conn] [-l logfile] [-t proxy_lifetime]"
            " [-g garbage collector interval]\n", name);
    exit(EXIT_SUCCESS);
}

/*
 * ip号翻译成16进制地址
 */
static void toip(char *ret, int address) {
	int a, b, c, d;

	a = (0xFF000000 & address) >> 24;
	b = (0x00FF0000 & address) >> 16;
	c = (0x0000FF00 & address) >> 8;
	d = 0x000000FF & address;

	snprintf(ret, 16, "%d.%d.%d.%d", a, b, c, d);
}

static char *conn_stat[] = {
	"PST_CLOSED",
	"PST_OPEN",
	"PST_CONNECT",
	"PST_PENDING",
};

static void logger_fn(void) {
	
}


