/*
 * AUTHOR: kiki, Wanta Fanta? ( gh0st <gh0st@rapturesecurity.org> )
 * "Yo man, i thought you was black!"
 *
 * this is GPL like the rest
 */
#include <config.h>

#include <signal.h>
#include <errno.h>

#include <pcap.h>

#include <scan_progs/packets.h>
#include <scan_progs/makepkt.h>
#include <unilib/pcaputil.h>
#include <unilib/pktutil.h>
#include <unilib/output.h>
#include <unilib/xmalloc.h>
#include <settings.h>

#include <dnet.h>

struct  myetheraddr {
	uint8_t octet[THE_ONLY_SUPPORTED_HWADDR_LEN];
};

struct _PACKED_ arp_packet {
	uint16_t hw_type;
	uint16_t protocol;
	uint8_t hwsize;
	uint8_t protosize;
	uint16_t opcode;
	uint8_t smac[THE_ONLY_SUPPORTED_HWADDR_LEN];
	uint32_t sip;
	uint8_t dmac[THE_ONLY_SUPPORTED_HWADDR_LEN];
	uint32_t dip;
};

struct {
	struct myetheraddr shwaddr;
	uint32_t saddr;
	uint32_t oaddr;
	uint32_t saddr_mask;
	uint8_t cidr;
	eth_t *e;
	char *device;
	int addr_cleared;
} bob;

static int send_arp(struct myetheraddr *, uint32_t);
static void process_packet(uint8_t *, const struct pcap_pkthdr *, const uint8_t *);
static void usage(void) _NORETURN_;
static void do_daemon(void);

settings_t *s=NULL;

const char *ident_name_ptr="Fnta";
int ident=0;

#ifdef HAVE_PCAP_SET_NONBLOCK
static int broadcast_arp(uint16_t, uint32_t);

static int breakloop=0;

static void alarm_hndlr(int signo) {

	breakloop=1;

	return;
}

static int broadcast_arp(uint16_t type, uint32_t addr) {
	uint8_t broadcast[6];
	const uint8_t *pbuf=NULL;
	size_t buf_size=0;

	memset(broadcast, 0xFF, 6);

	makepkt_clear();

	makepkt_build_ethernet(6, &broadcast[0], (uint8_t *)&bob.shwaddr.octet[0], ETHERTYPE_ARP);

	makepkt_build_arp(
				ARPHRD_ETHER,				/* ethernet		*/
				ETHERTYPE_IP,				/* proto for addr res	*/
				6,					/* hardware addr len	*/
				4,					/* proto addr len	*/
				type,					/* arp type		*/
				(uint8_t *)&bob.shwaddr.octet[0],	/* source		*/
				(uint8_t *)&addr,			/* ip src		*/
				&broadcast[0],				/* dst hw		*/
				(uint8_t *)&bob.saddr);			/* src ip		*/

	makepkt_getbuf(&buf_size, &pbuf);

	if (buf_size < 1 || pbuf == NULL) {
		ERR("makepkt fails, exiting");
		exit(1);
	}

	if (eth_send(bob.e, pbuf, buf_size) < 1) {
		ERR("eth_send fails, exiting");
		exit(1);
	}

	return 1;
}
#endif

static int send_arp(struct myetheraddr *dst, uint32_t dstip) {
	const uint8_t *pbuf=NULL;
	size_t buf_size=0;

	VRB(1, "sending ARP resp to: %s", decode_6mac((const uint8_t *)&dst->octet[0]));

	makepkt_clear();

	makepkt_build_ethernet(6,
				(uint8_t *)&dst->octet[0],		/* dest host hw addr	*/
				(uint8_t *)&bob.shwaddr.octet[0],	/* dest host src addr	*/
				ETHERTYPE_ARP);				/* ethernet, arp	*/

	makepkt_build_arp(
				ARPHRD_ETHER,				/* ethernet follows	*/
				ETHERTYPE_IP,				/* proto for addr res	*/
				6,					/* hardware addr len	*/
				4,					/* proto addr len	*/
				ARPOP_REPLY,				/* duh			*/
				(uint8_t *)&bob.shwaddr.octet[0],	/* source		*/
				(uint8_t *)&bob.saddr,			/* ip src		*/
				(uint8_t *)&dst->octet[0],		/* dst hw		*/
				(uint8_t *)&dstip);			/* dst ip		*/

	makepkt_getbuf(&buf_size, &pbuf);

	if (buf_size < 1 || pbuf == NULL) {
		ERR("makepkt fails, exiting");
		exit(1);
	}

	if (eth_send(bob.e, pbuf, buf_size) < 1) {
		ERR("eth_send fails, exiting");
		exit(1);
	}

	return 1;
}

#define FILTER "arp"

int main(int argc, char ** argv) {
	char errors[PCAP_ERRBUF_SIZE], pfilter[2048];
	char *hwaddr=NULL, *myip=NULL;
	struct ifreq ifr;
	bpf_u_int32 mask=0, net=0;
	struct bpf_program filter;
	pcap_t *pdev=NULL;
	int opt=0, detach=0;
#ifdef HAVE_PCAP_SET_NONBLOCK
	int tries=0;
#endif

	s=(settings_t *)xmalloc(sizeof(settings_t));

	s->_stdout=stdout;
	s->_stderr=stderr;

	memset(&ifr, 0, sizeof(ifr));

	while ((opt=getopt(argc, argv, "i:hH:dv")) != -1) {
		switch (opt) {
			case 'h':
				usage();
				break;
			case 'i':
				bob.device=xstrdup(optarg);
				break;
			case 'H':
				hwaddr=xstrdup(optarg);
				break;
			case 'd':
				detach=1;
				break;
			case 'v':
				s->verbose++;
				break;
			default:
				usage();
				break;
		}
	}

	if (optind < argc) {
		char *mptr=NULL;
		struct in_addr ia;

		myip=xstrdup(argv[optind]);
		if ((mptr=strrchr(myip, '/')) != NULL && strlen(mptr) > 1) {
			int i=0;

			*mptr='\0'; mptr++;
			bob.cidr=(uint8_t )(atoi(mptr) & 255);

			for (; i < bob.cidr; i++) {
				bob.saddr_mask=(bob.saddr_mask >> 1) | 0x80000000;
			}
		}
		else {
			bob.saddr_mask=0xFFFFFFFF;
			bob.cidr=32;
		}
		if (inet_aton(myip, &ia) == 0) {
			ERR("illegal IP address `%s'", myip);
			exit(1);
		}
		ia.s_addr &= htonl(bob.saddr_mask);
		xfree(myip);
		myip=xstrdup(inet_ntoa(ia));
		bob.oaddr=bob.saddr=ia.s_addr;
	}

	if (bob.saddr_mask != 0xffffffff) {
		uint8_t *p=NULL;
		uint32_t lmask=0;
		char highip[64];
		struct in_addr hi;

		lmask=ntohl(bob.saddr_mask);
		p=(uint8_t *)&lmask;
		hi.s_addr=bob.saddr | ~ntohl(bob.saddr_mask);

		sprintf(highip, "%s", inet_ntoa(hi));

		VRB(1, "using addresses `%s->%s/%u' (netmask %u.%u.%u.%u)", myip, highip, bob.cidr, *(p), *(p + 1), *(p + 2), *(p + 3));
	}
	else {
		VRB(1, "using address `%s'", myip);
	}

	if (myip == NULL) {
		ERR("IP address is required");
		usage();
	}

	if (bob.device == NULL) {
		ERR("interface argument is required");
		exit(1);
	}


	bob.e=eth_open(bob.device);
	if (bob.e == NULL) {
		ERR("cant open ethernet link: %s", strerror(errno));
		exit(1);
	}

	if (hwaddr != NULL) {
		uint32_t hws[6];
		uint8_t hwaddrs[6];

		if (sscanf(hwaddr, "%x:%x:%x:%x:%x:%x", &hws[0], &hws[1], &hws[2], &hws[3], &hws[4], &hws[5]) != 6) {
			ERR("bad hardware address, use XX:XX:XX:XX:XX:XX, not `%s'", hwaddr);
			exit(1);
		}
		if (hws[0] > 255 || hws[1] > 255 || hws[2] > 255 || hws[3] > 255 || hws[4] > 255 || hws[5] > 255) {
			ERR("no, thats not really going to work, sorry");
			exit(1);
		}

		hwaddrs[0]=(uint8_t)hws[0];
		hwaddrs[1]=(uint8_t)hws[1];
		hwaddrs[2]=(uint8_t)hws[2];
		hwaddrs[3]=(uint8_t)hws[3];
		hwaddrs[4]=(uint8_t)hws[4];
		hwaddrs[5]=(uint8_t)hws[5];

		VRB(0, "using hardware address %x:%x:%x:%x:%x:%x", hwaddrs[0], hwaddrs[1], hwaddrs[2], hwaddrs[3], hwaddrs[4], hwaddrs[5]);
		memcpy((void *)&bob.shwaddr, (void *)&hwaddrs[0], 6);
	}

	else if (eth_get(bob.e, (eth_addr_t *)&bob.shwaddr) < 0) {
		ERR("cant get hardware address: %s", strerror(errno));
		exit(1);
	}

	snprintf(pfilter, sizeof(pfilter) -1, FILTER);
	(void )pcap_lookupnet(bob.device, &net, &mask, errors);

	pdev=pcap_open_live(bob.device, 500, 1, -1, errors);
	if (pdev == NULL) {
		ERR("cant open up interface `%s': %s", bob.device, errors);
		exit(1);
	}

	if (util_getheadersize(pdev, errors) != 14) {
		ERR("you SURE this is an ethernet interface? doesnt look like one");
		pcap_close(pdev);
		exit(1);
	}

	if (util_preparepcap(pdev, errors) < 0) {
		ERR("cant prepare bpf socket: %s", strerror(errno));
		pcap_close(pdev);
		exit(1);
	}

	if (pcap_compile(pdev, &filter, pfilter, 0, net) < 0) {
		ERR("cant compile pcap filter `%s'", pfilter);
		pcap_close(pdev);
		exit(1);
	}

	if (pcap_setfilter(pdev, &filter) < 0) {
		ERR("cant set pcap filter");
		pcap_close(pdev);
		exit(1);
	}

#ifdef HAVE_PCAP_SET_NONBLOCK
	/* look for dups */
	if (pcap_setnonblock(pdev, 1, errors) < 0) {
		ERR("can't set pcap dev nonblocking: %s", errors);
		exit(1);
	}

	signal(SIGALRM, &alarm_hndlr);

	do {
		for (bob.addr_cleared=0, tries=0; bob.addr_cleared == 0 && tries < 3; tries++) {
			VRB(2, "testing `%s'", inet_ntoa(*((struct in_addr *)&bob.saddr)));
			/* lets be sure about this */
			broadcast_arp(ARPOP_REQUEST, 0xFFFFFFFF);
			broadcast_arp(ARPOP_REQUEST, 0x00000000);
			broadcast_arp(ARPOP_REQUEST, bob.saddr);

			alarm(1);

			for (breakloop=0, bob.addr_cleared=0 ; breakloop == 0 && bob.addr_cleared == 0; ) {
				pcap_dispatch(pdev, -1, process_packet, NULL);
				usleep(10000);
			}

			alarm(0);
		}

		alarm(0);

		if (bob.addr_cleared == -1) {
			ERR("error: Address already in use");
			pcap_close(pdev);
			eth_close(bob.e);
			exit(1);
		}

		bob.saddr += htonl(1);
		if (1) {
			uint32_t max, cur, lmask;

			lmask=ntohl(bob.saddr_mask);
			max=ntohl(bob.oaddr | ~lmask);
			cur=ntohl(bob.saddr);
			if (cur == 0xffffffff || cur > max) {
				bob.addr_cleared=1;
				break;
			}
		}
	} while (1);

	signal(SIGALRM, SIG_DFL);

#else
# warning no pcap_setnonblock
#endif /* pcap_setnonblock */

	if (detach) {
		VRB(1, "going into background");

		s->verbose=0;
		s->debugmask=0;

		do_daemon();
	}

	bob.saddr=bob.oaddr;

	VRB(0, "arping for %s/%u [%s]", inet_ntoa(*((const struct in_addr *)&bob.saddr)), bob.cidr, decode_6mac((const uint8_t *)&bob.shwaddr.octet[0]));

#ifdef HAVE_PCAP_SET_NONBLOCK
	/* ok block now */
	if (pcap_setnonblock(pdev, 0, errors) < 0) {
		ERR("cant set pcap dev nonblocking: %s", errors);
		pcap_close(pdev);
		eth_close(bob.e);
		exit(1);
	}
#endif

	for (;;) {
		if (pcap_dispatch(pdev, -1, process_packet, NULL) == 0) {
			usleep(1000);
		}
	}

	eth_close(bob.e);
	pcap_close(pdev);

	exit(0);
}

void process_packet(uint8_t *user, const struct pcap_pkthdr *phdr, const uint8_t *packet) {
	const struct ether_header *ehdr_ptr=NULL;
	const struct arp_packet *ap=NULL;

	if (phdr->caplen != phdr->len || phdr->caplen < sizeof(struct ether_header)) {
		ERR("bad length");
		return;
	}
 
	ehdr_ptr=(const struct ether_header *)packet;

	if (ntohs(ehdr_ptr->ether_type) != ETHERTYPE_ARP) {
		ERR("NON ETHERNET ARP");
		return;
	}
	ap=(const struct arp_packet *)(packet + sizeof(struct ether_header));
	if (phdr->caplen < (sizeof(struct ether_header) + sizeof(struct arp_packet))) {
		ERR("short packet!!!!");
		return;
	}

	DBG(M_PKT, "got packet hw type %u proto %x hwsize %x protosize %x", ntohs(ap->hw_type), ntohs(ap->protocol), ap->hwsize, ap->protosize);

	/* ethernet -> ip -> hwsize = 6 and ip size = 4 */
	if (ntohs(ap->hw_type) == 1 && ntohs(ap->protocol) == 0x800 && ap->hwsize == 6 && ap->protosize == 4) {
		char src[17], dst[17];
		char tmphw[32];

		switch (ntohs(ap->opcode)) {
			case 1:
				/* arp request */
				if (s->verbose > 2) { 
					char rbuf[256];

					snprintf(tmphw, sizeof(tmphw) -1, "%s", decode_6mac(ap->smac));
					snprintf(rbuf, sizeof(rbuf) -1, "Arp Request: Source Mac: %s Dest Mac: %s",
						tmphw, decode_6mac(ap->dmac));
					/* hide the children, they will cry if they see this */
					snprintf(src, sizeof(src) -1, "%s", inet_ntoa(*((const struct in_addr *)&ap->sip)));
					snprintf(dst, sizeof(dst) -1, "%s", inet_ntoa(*((const struct in_addr *)&ap->dip)));
					DBG(M_PKT, "%s [ %s -> %s ]", rbuf, src, dst);
				}

				if (bob.addr_cleared) {
					uint32_t min, max, req;

					min=ntohl(bob.saddr);
					max=ntohl(bob.saddr) | ~(bob.saddr_mask);
					req=ntohl(ap->dip);

					if (min <= req && req <= max) {
						struct myetheraddr sea;

						memset(&sea, 0, sizeof(sea));
						memcpy(&(sea.octet[0]), &ap->smac[0], 6);

						bob.saddr=htonl(req);
						send_arp((struct myetheraddr *)&sea, ap->sip);
						bob.saddr=bob.oaddr;
					}
				}
				break;
			case 2: /* reply */
				if (s->verbose > 2) {
					char rbuf[256];

					snprintf(tmphw, sizeof(tmphw) -1, "%s", decode_6mac(ap->smac));
					snprintf(rbuf, sizeof(rbuf) -1, "Arp Reply: Source Mac: %s Dest Mac: %s",
						tmphw, decode_6mac(ap->dmac));
					/* hide the children, they will cry if they see this */
					snprintf(src, sizeof(src) -1, "%s", inet_ntoa(*((const struct in_addr *)&ap->sip)));
					snprintf(dst, sizeof(dst) -1, "%s", inet_ntoa(*((const struct in_addr *)&ap->dip)));
					DBG(M_PKT, "%s [ %s -> %s ]", rbuf, src, dst);
				}

				if (bob.addr_cleared == 0 && ap->sip == bob.saddr) {
					bob.addr_cleared=-1;
				}
				break;
			default:
				break;
		}
	}

	return;
}

void do_daemon(void) {
	pid_t child=0;

	child=fork();
	if (child < 0) {
		ERR("cant fork: %s", strerror(errno));
		exit(1);
	}
	else if (child == 0) {
		setsid();
		chdir("/");
		umask(777);
		freopen("/dev/null", "r", stdin);
		freopen("/dev/null", "w", stdout);
		freopen("/dev/null", "w", stderr);

		return;
	}
	else {
		exit(0);
	}
}

void usage(void) {
	OUT("FantaIP by Kiki\nUsage: fantaip (options) IP\n"
		"\t-d\t\tDetach from terminal and daemonize\n"
		"\t-H\t\tHardware address like XX:XX:XX:XX:XX:XX (otherwise use nics hwaddr)\n"
		"\t-h\t\thelp\n"
		"\t-i\t\t*interface\n"
		"\t-v\t\tverbose operation\n"
		"*: Argument required\n"
		"Example: fantaip -i eth0 192.168.1.7");

	exit(0);
}
