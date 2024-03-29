#include <arpa/inet.h>
#include <endian.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "QMIThread.h"
#include "util.h"

static int dibbler_client_alive = 0;

static int fibo_system(const char *shell_cmd)
{
    int ret = 0;
    dbg_time("%s", shell_cmd);
    ret = system(shell_cmd);
    if (ret) {
	// dbg_time("Fail to system(\"%s\") = %d, errno: %d (%s)", shell_cmd,
	// ret, errno, strerror(errno));
    }
    return ret;
}

static void fibo_set_mtu(const char *ifname, int ifru_mtu)
{
    int inet_sock;
    struct ifreq ifr;

    inet_sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (inet_sock > 0) {
	strcpy(ifr.ifr_name, ifname);

	if (!ioctl(inet_sock, SIOCGIFMTU, &ifr)) {
	    if (ifr.ifr_ifru.ifru_mtu != ifru_mtu) {
		dbg_time("change mtu %d -> %d", ifr.ifr_ifru.ifru_mtu,
			 ifru_mtu);
		ifr.ifr_ifru.ifru_mtu = ifru_mtu;
		ioctl(inet_sock, SIOCSIFMTU, &ifr);
	    }
	}

	close(inet_sock);
    }
}

static void *udhcpc_thread_function(void *arg)
{
    FILE *udhcpc_fp;
    char *udhcpc_cmd = (char *)arg;

    if (udhcpc_cmd == NULL)
	return NULL;

    dbg_time("%s", udhcpc_cmd);
    udhcpc_fp = popen(udhcpc_cmd, "r");
    free(udhcpc_cmd);
    if (udhcpc_fp) {
	char buf[0xff];

	buf[sizeof(buf) - 1] = '\0';
	while ((fgets(buf, sizeof(buf) - 1, udhcpc_fp)) != NULL) {
	    if ((strlen(buf) > 1) && (buf[strlen(buf) - 1] == '\n'))
		buf[strlen(buf) - 1] = '\0';
	    dbg_time("%s", buf);
	}

	pclose(udhcpc_fp);
    }

    return NULL;
}


void fibo_set_driver_link_state(PROFILE_T *profile, int link_state)
{
    char link_file[128];
    int fd;
    int new_state = 0;
    dbg_time("enter %s ", __func__);

    snprintf(link_file, sizeof(link_file), "/sys/class/net/%s/link_state",
	     profile->usbnet_adapter);
    fd = open(link_file, O_RDWR | O_NONBLOCK | O_NOCTTY);
    if (fd == -1) {
	if (errno != ENOENT)
	    dbg_time("Fail to access %s, errno: %d (%s)", link_file, errno,
		     strerror(errno));
	return;
    }

    if (profile->qmap_mode <= 1)
	new_state = !!link_state;
    else {
	// 0x80 means link off this pdp
	new_state = (link_state ? 0x00 : 0x80) + profile->pdp;
    }

    snprintf(link_file, sizeof(link_file), "%d\n", new_state);
    write(fd, link_file, sizeof(link_file));

    if (link_state == 0  && profile->qmapnet_adapter && strcmp(profile->qmapnet_adapter, profile->usbnet_adapter)) {
	size_t rc;

	lseek(fd, 0, SEEK_SET);
	rc = read(fd, link_file, sizeof(link_file));
	if (rc > 1 && (!strncasecmp(link_file, "0\n", 2) || !strncasecmp(link_file, "0x0\n", 4))) {
	    snprintf(link_file, sizeof(link_file), "busybox ifconfig %s down",
		     profile->usbnet_adapter);
	    fibo_system(link_file);
	}
    }

    close(fd);
}

static void ifc_init_ifr(const char *name, struct ifreq *ifr)
{
    memset(ifr, 0, sizeof(struct ifreq));
    strncpy(ifr->ifr_name, name, IFNAMSIZ);
    ifr->ifr_name[IFNAMSIZ - 1] = 0;
}

static short ifc_get_flags(const char *ifname)
{
    int inet_sock;
    struct ifreq ifr;
    int ret = 0;

    inet_sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (inet_sock > 0) {
        ifc_init_ifr(ifname, &ifr);

        if (!ioctl(inet_sock, SIOCGIFFLAGS, &ifr)) {
            ret = ifr.ifr_ifru.ifru_flags;
        }

        close(inet_sock);
    }

    return ret;
}

static const char *ipv4Str(const uint32_t Address) {
    static char str[] = {"255.225.255.255"};
    uint8_t *ip = (uint8_t *)&Address;

    snprintf(str, sizeof(str), "%d.%d.%d.%d", ip[3], ip[2], ip[1], ip[0]);
    return str;
}

static const char *ipv6Str(const UCHAR Address[16]) {
    static char str[64];
    uint16_t ip[8];
    int i;
    for (i = 0; i < 8; i++) {
        ip[i] = (Address[i*2]<<8) + Address[i*2+1];
    }

    snprintf(str, sizeof(str), "%x:%x:%x:%x:%x:%x:%x:%x",
        ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7]);

    return str;
}
int fibo_raw_ip_mode_check(const char *ifname)
{
    int fd;
    char raw_ip[128];
    char shell_cmd[128];
    char mode[2] = "X";
    int mode_change = 0;

    snprintf(raw_ip, sizeof(raw_ip), "/sys/class/net/%s/qmi/raw_ip", ifname);
    if (access(raw_ip, F_OK))
	return 0;

    fd = open(raw_ip, O_RDWR | O_NONBLOCK | O_NOCTTY);
    if (fd < 0) {
	dbg_time("%s %d fail to open(%s), errno:%d (%s)", __FILE__, __LINE__,
		 raw_ip, errno, strerror(errno));
	return 0;
    }

    read(fd, mode, 2);
    if (mode[0] == '0' || mode[0] == 'N') {
	snprintf(shell_cmd, sizeof(shell_cmd), "busybox ifconfig %s down", ifname);
	fibo_system(shell_cmd);
	dbg_time("echo Y > /sys/class/net/%s/qmi/raw_ip", ifname);
	mode[0] = 'Y';
	write(fd, mode, 2);
	mode_change = 1;
	snprintf(shell_cmd, sizeof(shell_cmd), "busybox ifconfig %s up", ifname);
	fibo_system(shell_cmd);
    }

    close(fd);
    return mode_change;
}

void udhcpc_start(PROFILE_T *profile)
{
    char *ifname = profile->usbnet_adapter;
    char shell_cmd[128];
    FILE *fp = NULL;
    char line_buf[320] = {0};

    fibo_set_driver_link_state(profile, 1);
    if (profile->qmapnet_adapter) {
	ifname = profile->qmapnet_adapter;
    }
    dbg_time("1 %s", profile->qmichannel);
    if (qmidev_is_qmiwwan(profile->qmichannel)) {
	dbg_time("2 %s", ifname);
	fibo_raw_ip_mode_check(ifname);
    }

    if (profile->rawIP && profile->ipv4.Address && profile->ipv4.Mtu) {
	fibo_set_mtu(ifname, (profile->ipv4.Mtu));
    }

     //fibo_system("echo 1 > /sys/module/fibo_mhi/parameters/macaddr_check");
     
//begin modified by zhangkaibo fix ipv6 dial process flow. mantis 0048789 20200605	
//  if (strcmp(ifname, profile->usbnet_adapter)) {
//	snprintf(shell_cmd, sizeof(shell_cmd) - 1, "busybox ifconfig %s up",
//		 profile->usbnet_adapter);
//	fibo_system(shell_cmd);
//  }
//begin modified by zhangkaibo fix ipv6 dial process flow. mantis 0048789 20200605	
    // For IPv6, down & up will send protocol packets, and that's needed.

    if (strcmp(ifname, profile->usbnet_adapter)) {
        snprintf(shell_cmd, sizeof(shell_cmd), "busybox ifconfig %s up", profile->usbnet_adapter);
        fibo_system(shell_cmd);
        if (ifc_get_flags(ifname)&IFF_UP) {
            snprintf(shell_cmd, sizeof(shell_cmd), "busybox ifconfig %s down", ifname);
            fibo_system(shell_cmd);
            snprintf(shell_cmd, sizeof(shell_cmd), "ifconfig %s down", ifname);
            fibo_system(shell_cmd);
        }
    }



    snprintf(shell_cmd, sizeof(shell_cmd) - 1, "busybox ifconfig %s up", ifname);
    fibo_system(shell_cmd);

    snprintf(shell_cmd, sizeof(shell_cmd) - 1, " ifconfig %s | grep inet |grep inet6", ifname);
    fp = popen(shell_cmd, "r");
    if (fp != NULL)
    {
        memset((void*)line_buf, 0, sizeof(line_buf));
        if(NULL != fgets(line_buf, sizeof(line_buf) - 1, fp))
        {
            dbg_time( "line_buf=%s\n", line_buf);
        }
        pclose(fp);
        if(strlen(line_buf) == 0){
            snprintf(shell_cmd, sizeof(shell_cmd) - 1, "dhclient -I %s", ifname);
            fibo_system(shell_cmd);
            }
    }


	//begin modified by zhangming Added NOARP and Multilcast on flag bit commands. mantis 0050106 20200713 
	//snprintf(shell_cmd, sizeof(shell_cmd) - 1, "ip link set %s arp off multicast on", ifname);
    //fibo_system(shell_cmd);
	//begin modified by zhangming Added NOARP and Multilcast on flag bit commands. mantis 0050106 20200713	
	//Modified unicom dual stack dialing unsuccessful problem

    // for bridge mode, only one public IP, so do udhcpc manually
    if (fibo_bridge_mode_detect(profile)) {
	return;
    }

    /* Do DHCP using busybox tools */
    {
	char udhcpc_cmd[128];
	pthread_attr_t udhcpc_thread_attr;
	pthread_t udhcpc_thread_id;

	pthread_attr_init(&udhcpc_thread_attr);
	pthread_attr_setdetachstate(&udhcpc_thread_attr,
				    PTHREAD_CREATE_DETACHED);

	if (profile->ipv4.Address) {
	    if (access("/usr/share/udhcpc/default.script", X_OK)) {
		dbg_time(
		    "Fail to access /usr/share/udhcpc/default.script, "
		    "errno: %d (%s)",
		    errno, strerror(errno));
	    }

	    //-f,--foreground    Run in foreground
	    //-b,--background    Background if lease is not obtained
	    //-n,--now        Exit if lease is not obtained
	    //-q,--quit        Exit after obtaining lease
	    //-t,--retries N        Send up to N discover packets (default 3)
	    snprintf(udhcpc_cmd, sizeof(udhcpc_cmd),
		     "busybox udhcpc -f -n -q -t 5 -i %s", ifname);

	    if (!access("/lib/netifd/dhcp.script", X_OK) &&
		!access("/sbin/ifup", X_OK) &&
		!access("/sbin/ifstatus", X_OK)) {
		dbg_time("you are use OpenWrt?");
		dbg_time("should not calling udhcpc manually?");
		dbg_time("should modify /etc/config/network as below?");
		dbg_time("config interface wan");
		dbg_time("\toption ifname	%s", ifname);
		dbg_time("\toption proto	dhcp");
		dbg_time(
		    "should use \"/sbin/ifstaus wan\" to check %s 's status?",
		    ifname);
	    }

	    pthread_create(&udhcpc_thread_id, NULL, udhcpc_thread_function,
			   (void *)strdup(udhcpc_cmd));
	    sleep(1);
	}

	if (profile->ipv6.Address[0] && profile->ipv6.PrefixLengthIPAddr) {
	    // module do not support DHCPv6, only support 'Router Solicit'
	    // and it seem if enable /proc/sys/net/ipv6/conf/all/forwarding,
	    // Kernel do not send RS
	    const char *forward_file = "/proc/sys/net/ipv6/conf/all/forwarding";
	    int forward_fd = open(forward_file, O_RDONLY);
	    if (forward_fd > 0) {
		char forward_state[2];
		read(forward_fd, forward_state, 2);
		if (forward_state[0] == '1') {
		    dbg_time(
			"%s enabled, kernel maybe donot send 'Router Solicit'",
			forward_file);
		}
		close(forward_fd);
	    }
        snprintf(shell_cmd, sizeof(shell_cmd), "ip -%d address add %s/%u dev %s",
            6, ipv6Str(profile->ipv6.Address), profile->ipv6.PrefixLengthIPAddr, ifname);
        fibo_system(shell_cmd);
        
        //ping6 www.qq.com
        snprintf(shell_cmd, sizeof(shell_cmd), "ip -%d route add default via %s dev %s",
            6, ipv6Str(profile->ipv6.Gateway), ifname);
        fibo_system(shell_cmd);
        
        if (profile->ipv6.DnsPrimary[0] || profile->ipv6.DnsSecondary[0]) {
            char dns1str[64], dns2str[64];
        
            if (profile->ipv6.DnsPrimary[0]) {
                strcpy(dns1str, ipv6Str(profile->ipv6.DnsPrimary));
            }
        
            if (profile->ipv6.DnsSecondary[0]) {
                strcpy(dns2str, ipv6Str(profile->ipv6.DnsSecondary));
            }
            
            update_resolv_conf(6, ifname, profile->ipv6.DnsPrimary[0] ? dns1str : NULL, profile->ipv6.DnsSecondary ? dns2str : NULL);
            }
	}
    }
}

void udhcpc_stop(PROFILE_T *profile)
{
    char *ifname = profile->usbnet_adapter;
    char shell_cmd[128];
    char reset_ip[128];
    dbg_time("enter %s ", __func__);
    fibo_set_driver_link_state(profile, 0);

    if (profile->qmapnet_adapter) {
	ifname = profile->qmapnet_adapter;
    }

    if (dibbler_client_alive) {
	system("killall dibbler-client");
	dibbler_client_alive = 0;
    }
    //snprintf(shell_cmd, sizeof(shell_cmd) - 1, "busybox ifconfig %s down",
    //	     profile->usbnet_adapter);
    //fibo_system(shell_cmd);
    snprintf(reset_ip, sizeof(reset_ip) - 1, "busybox ifconfig %s 0.0.0.0", ifname);
    fibo_system(reset_ip);
    snprintf(shell_cmd, sizeof(shell_cmd) - 1, "busybox ifconfig %s down", ifname);
    fibo_system(shell_cmd);

}
