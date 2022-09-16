/*

ptpmeasure: An ST 2110/2022-6 PTP measurement tool
Copyright (C) 2022 Open Broadcast Systems Ltd

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

*/

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

#include <inttypes.h>

#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>
#include <ifaddrs.h>

#include <bitstream/ieee/ethernet.h>
#include <bitstream/ietf/ip.h>
#include <bitstream/ietf/udp.h>
#include <bitstream/ietf/rtp.h>
#include <bitstream/smpte/2022_6_hbrmt.h>

#include <pcap.h>

#define LEAP_SECONDS (37)

#   define AV_RB32(x)                                \
    (((uint32_t)((const uint8_t*)(x))[0] << 24) |    \
               (((const uint8_t*)(x))[1] << 16) |    \
               (((const uint8_t*)(x))[2] <<  8) |    \
                ((const uint8_t*)(x))[3])

static bool mellanox = false;

struct rational {
    uint16_t num, den;
} fps;

static inline int time_for_log(char buf[256])
{
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(buf, 256, "%Y-%m-%d %H:%M:%S%z", &tm);
    return 0;
}

void got_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    pcap_t *pcap = (pcap_t*)user;
    uint8_t *eth_payload = ethernet_payload((uint8_t*)packet);
    uint8_t *ip_pkt = ip_payload(eth_payload);
    uint8_t *udp_pkt = udp_payload(ip_pkt);
    uint8_t *rtp_data = rtp_payload(udp_pkt);
    uint32_t rtp_timestamp = rtp_get_timestamp(udp_pkt);

    /* Add leap seconds to convert from PC time to TAI */
    uint64_t ptp_timestamp;
    if (mellanox)
        ptp_timestamp = header->ts.tv_sec;
    else
        ptp_timestamp = AV_RB32(&packet[header->len-9]) + LEAP_SECONDS;
    ptp_timestamp *= 48000;
    if (mellanox)
        ptp_timestamp += header->ts.tv_usec * 48000 / 1000000;
    else
        ptp_timestamp += AV_RB32(&packet[header->len-5]) * (uint64_t)48000 / 1e9;
    ptp_timestamp &= UINT32_MAX;

    int64_t delta = (int64_t)rtp_timestamp - ptp_timestamp;
    int len = header->len - (rtp_data - (uint8_t*)packet) - ((mellanox) ? 0 : 9);

    char time_buf[256];
    if (time_for_log(time_buf))
        pcap_breakloop(pcap);

    printf("%s: RTP-PTP offset %f us. Audio samples %i \n",
            time_buf, (float)delta*1e6/48000, len/3);
}

void got_packet_2110_video(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    pcap_t *pcap = (pcap_t*)user;
    uint8_t *ip_pkt = ethernet_payload((uint8_t*)packet);
    uint8_t *udp_pkt = ip_payload(ip_pkt);
    uint8_t *rtp_pkt = udp_payload(udp_pkt);

    static bool prev_marker = false;
    bool marker = rtp_check_marker(rtp_pkt);

    if (!prev_marker) {
        prev_marker = marker;
        return;
    }
    prev_marker = marker;

    uint32_t rtp_timestamp = rtp_get_timestamp(rtp_pkt);

    uint64_t arrival_time_90khz, arrival_time_ns;
    if (mellanox)
        arrival_time_ns = arrival_time_90khz = header->ts.tv_sec;
    else
        /* Add leap seconds to convert from PC time to TAI */
        arrival_time_ns = arrival_time_90khz = AV_RB32(&packet[header->len-9]) + LEAP_SECONDS;

    arrival_time_90khz *= 90000;
    arrival_time_ns *= 1000000000;

    if (mellanox) {
        arrival_time_90khz += header->ts.tv_usec * 90000 / 1000000;
        arrival_time_ns += header->ts.tv_usec * 1000;
    } else {
        arrival_time_90khz += AV_RB32(&packet[header->len-5]) * UINT64_C(90000) / UINT64_C(1000000000);
        arrival_time_ns += AV_RB32(&packet[header->len-5]);
    }
    arrival_time_90khz &= UINT32_MAX;

    const uint64_t frame_time_ns = UINT64_C(1000000000) * fps.den;
    __uint128_t temp = fps.num;
    temp *= arrival_time_ns;
    temp %= frame_time_ns;
    uint64_t ideal_ptp_diff_ns = temp;

    temp = arrival_time_ns - ideal_ptp_diff_ns / fps.num;
    temp = temp * 90000 / 1000000000;
    temp = temp & UINT32_MAX;
    int64_t delta = (int64_t)rtp_timestamp - (int64_t)temp;

    char time_buf[256];
    if (time_for_log(time_buf))
        pcap_breakloop(pcap);

    if (ideal_ptp_diff_ns > frame_time_ns / 2) {
        printf("%s: First packet arrived %.3f ms before ideal, RTP-PTP offset %.3fus (%"PRId64" rtp).\n",
                time_buf,
                (frame_time_ns - ideal_ptp_diff_ns) / (1e6 * fps.num),
                delta*1e6/90000, delta);
    }

    else {
        printf("%s: First Packet arrived %.3f ms after ideal,  RTP-PTP offset %.3fus (%"PRId64" rtp).\n",
                time_buf,
                ideal_ptp_diff_ns / (1e6 * fps.num),
                delta*1e6/90000, delta);
    }
}

void got_packet_2022_6(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    pcap_t *pcap = (pcap_t*)user;
    uint8_t *ip_pkt = ethernet_payload((uint8_t*)packet);
    uint8_t *udp_pkt = ip_payload(ip_pkt);
    uint8_t *rtp_pkt = udp_payload(udp_pkt);
    if (!rtp_check_marker(rtp_pkt))
        return;

    if (rtp_get_type(rtp_pkt) != 98)
        printf("Error: RTP type not correct\n");

    uint8_t *hbrmt_pkt = rtp_payload(rtp_pkt);
    uint8_t header_frate = smpte_hbrmt_get_frate(hbrmt_pkt);
    if (header_frate < 0x10 || header_frate > 0x1b)
        printf("Error: HBRMT frame rate out of range\n");

    static const struct rational fps[] = {
        [0x10] = { 60,       1 },
        [0x11] = { 60000, 1001 },
        [0x12] = { 50,       1 },
        [0x14] = { 48,       1 },
        [0x15] = { 48000, 1001 },
        [0x16] = { 30,       1 },
        [0x17] = { 30000, 1001 },
        [0x18] = { 25,       1 },
        [0x1a] = { 24,       1 },
        [0x1b] = { 24000, 1001 },
    };
    const uint64_t frame_time = UINT64_C(1000000000) * fps[header_frate].den;

    uint8_t header_frame = smpte_hbrmt_get_frame(hbrmt_pkt);
    uint32_t frame_size = 0;
    /* NTSC */
    if (header_frame == 0x10)
        frame_size = 858 * 525 / 2 * 5;

    /* PAL */
    else if (header_frame == 0x11)
        frame_size = 864 * 625 / 2 * 5;

    /* 720 lines */
    else if (header_frame == 0x30) {
        if (header_frate == 0x12)
            frame_size = 1980 * 750 / 2 * 5;
        else
            frame_size = 1650 * 750 / 2 * 5;
    }

    /* 1080 lines */
    else if (header_frame == 0x20 || header_frame == 0x21) {
        if (header_frate == 0x1b || header_frate == 0x1a)
            frame_size = 2750 * 1125 / 2 * 5;
        else if (header_frate == 0x18 || header_frate == 0x12)
            frame_size = 2640 * 1125 / 2 * 5;
        else
            frame_size = 2200 * 1125 / 2 * 5;
    }

    double packet_time = frame_time
        / (((frame_size + HBRMT_DATA_SIZE-1) / HBRMT_DATA_SIZE) * fps[header_frate].num);

    char time_buf[256];
    if (time_for_log(time_buf))
        pcap_breakloop(pcap);

    uint64_t recv_timestamp;
    if (mellanox) {
        recv_timestamp = header->ts.tv_sec * UINT64_C(1000000000) + header->ts.tv_usec * 1000;
    } else {
        uint32_t ts1 = AV_RB32(&packet[header->len-9]) + LEAP_SECONDS;
        uint32_t ts2 = AV_RB32(&packet[header->len-5]);
        recv_timestamp = ts1 * UINT64_C(1000000000) + ts2;
    }

    __uint128_t temp = fps[header_frate].num;
    temp *= recv_timestamp;
    temp %= frame_time;
    uint64_t ptp_epoch_diff = temp;

    static int64_t box[25] = {0};
    static unsigned counter = 0;
    static int64_t sum = 0;

    if (ptp_epoch_diff > frame_time / 2) {
        sum -= box[counter];
        box[counter] = (int64_t)ptp_epoch_diff - (int64_t)frame_time;
        sum += box[counter];
        printf("%s: Marker arrived %.3f ms before epoch, %2.1f packets off, rolling average: %.3f\n",
                time_buf,
                (frame_time - ptp_epoch_diff) / (1e6 * fps[header_frate].num),
                (frame_time - ptp_epoch_diff) / (packet_time * fps[header_frate].num),
                sum / (25e6 * fps[header_frate].num));
    }
    else {
        sum -= box[counter];
        box[counter] = ptp_epoch_diff;
        sum += box[counter];
        printf("%s: Marker arrived %.3f ms after epoch,  %2.1f packets off, rolling average: %.3f\n",
                time_buf,
                ptp_epoch_diff / (1e6 * fps[header_frate].num),
                ptp_epoch_diff / (packet_time * fps[header_frate].num),
                sum / (25e6 * fps[header_frate].num));
    }

    counter = (counter + 1) % 25;
}

enum {
    OPT = 9000,
    OPT_2022_6,
    OPT_2110_VIDEO,
};

static const struct option cmd_options[] = {
    { "2022-6",              no_argument, NULL, OPT_2022_6 },
    { "2110-video",          no_argument, NULL, OPT_2110_VIDEO },
    { "fps",           required_argument, NULL, 'f' },
    { "help",                no_argument, NULL, 'h' },
    { "interlaced",          no_argument, NULL, 'i' },
    { "list-ts-types",       no_argument, NULL, 'l' },
    { "mellanox",            no_argument, NULL, 'm' },
    { "packet-count",  required_argument, NULL, 'c' },
    { "ts-type",       required_argument, NULL, 't' },
    { NULL }
};

#define lengthof(a) ((int)(sizeof(a) / sizeof(a[0])))

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [options] <mmulticast group> <port> <interface name>\n"
                    "Example: %s 239.255.255.250 1900 p9p1\n", prog, prog);
    fprintf(stderr, "long options:\n");
    for (int i = 0; i < lengthof(cmd_options) - 1; i++) {
        if (cmd_options[i].val > 0x20 && cmd_options[i].val < 0x7f)
            fprintf(stderr, "    -%c, --%s\n", cmd_options[i].val, cmd_options[i].name);
        else
            fprintf(stderr, "        --%s\n", cmd_options[i].name);
    }
}

#define UBASE_CASE_TO_STR(Value)        case Value: return #Value

static const char *pcap_error(pcap_t *p, int value)
{
    switch (value) {
        UBASE_CASE_TO_STR(PCAP_ERROR_ACTIVATED);
        UBASE_CASE_TO_STR(PCAP_ERROR_CANTSET_TSTAMP_TYPE);
        UBASE_CASE_TO_STR(PCAP_ERROR_IFACE_NOT_UP);
        UBASE_CASE_TO_STR(PCAP_ERROR_NO_SUCH_DEVICE);
        UBASE_CASE_TO_STR(PCAP_ERROR_PERM_DENIED);
        UBASE_CASE_TO_STR(PCAP_ERROR_PROMISC_PERM_DENIED);
        UBASE_CASE_TO_STR(PCAP_ERROR_RFMON_NOTSUP);
        UBASE_CASE_TO_STR(PCAP_WARNING_PROMISC_NOTSUP);
        UBASE_CASE_TO_STR(PCAP_WARNING_TSTAMP_TYPE_NOTSUP);
        case PCAP_ERROR: return pcap_geterr(p);
        case PCAP_WARNING: return pcap_geterr(p);
        default: return "unknown error";
    }
}

int main(int argc, char *argv[])
{
    int i = 0;
    char filter_exp[100];
    bool opt_2022_6 = false, opt_2110_video = false, list_ts = false;
    bool interlaced = false;
    int packet_count = -1;
    int ret = 0;
    const char *ts_type = NULL;

    int opt;
    while ((opt = getopt_long(argc, argv, "c:f:hilmt:", cmd_options, NULL)) != -1) switch (opt) {
        case OPT_2022_6:
            opt_2022_6 = true;
            break;

        case OPT_2110_VIDEO:
            opt_2110_video = true;
            break;

        case 'c':
            packet_count = atoi(optarg);
            break;

        case 'f': {
            int num = 0, den = 0;
            char c;
            if (sscanf(optarg, "%d/%d%c", &num, &den, &c) != 2) {
                fprintf(stderr, "unable to parse %s as framerate\n", optarg);
                return 1;
            }
            if (num <= 0 || num > 60000 || den <= 0 || den > 1001) {
                fprintf(stderr, "invalid framerate given: %d/%d\n", num, den);
            }
            fps = (struct rational) { num, den };
        } break;

        case 'i':
            interlaced = true;
            break;

        case 'l':
            list_ts = true;
            break;

        case 'm':
            mellanox = true;
            break;

        case 't':
            ts_type = optarg;
            break;

        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
    }

    if (optind + 3 != argc) {
        usage(argv[0]);
        return 1;
    }

    if (opt_2110_video && fps.num == 0) {
        fprintf(stderr, "2110 video requires that you give the frame rate with --fps, and --interlaced if necessary\n");
        return 1;
    }

    if (interlaced)
        fps.num *= 2;

    if (mellanox && ts_type == NULL)
        ts_type = "adapter_unsynced";

    char *group = argv[optind + 0];
    int port = atoi(argv[optind + 1]);
    char *miface = argv[optind + 2];
    char errbuf[PCAP_ERRBUF_SIZE];

    struct sockaddr_in ip_src_addr;
    char *ip_src = NULL, *ip_dst = NULL;
    ip_dst = strchr(group, '@');
    if (ip_dst) {
        *ip_dst = '\0';
        ip_dst++;
        ip_src = group;

        struct ifaddrs *ifa = NULL;
        if (getifaddrs(&ifa) < 0) {
            ret = errno;
            fprintf(stderr, "getifaddrs: %m\n");
            return ret;
        }

        bool have_sin = false;
        for (struct ifaddrs *ifap = ifa; ifap; ifap = ifap->ifa_next) {
            if (!strncmp(ifap->ifa_name, miface, IFNAMSIZ)) {
                if (ifap->ifa_addr->sa_family == AF_INET) {
                    ip_src_addr = *(struct sockaddr_in *)ifap->ifa_addr;
                    have_sin = true;
                    break;
                }
            }
        }
        freeifaddrs(ifa);

        if (!have_sin) {
            fprintf(stderr, "unable to get IP address for %s\n", miface);
            return 1;
        }
    }

    else {
        ip_dst = group;
    }


    struct bpf_program fp;		/* The compiled filter expression */
    bpf_u_int32 mask;		/* The netmask of our sniffing device */
    bpf_u_int32 net;		/* The IP of our sniffing device */

    if(pcap_lookupnet(miface, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", miface);
        net = 0;
        mask = 0;
    }

    pcap_t *pcap = pcap_create(miface, errbuf);
    if(pcap == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", miface, errbuf);
        return -1;
    }

    if (list_ts) {
        int *list;
        int num = pcap_list_tstamp_types(pcap, &list);
        if (num == PCAP_ERROR) {
            pcap_perror(pcap, "pcap_list_tstamp_types");
            return -1;
        }

        for (int i = 0; i < num; i++) {
            const char *name = pcap_tstamp_type_val_to_name(list[i]);
            const char *desc = pcap_tstamp_type_val_to_description(list[i]);
            if (!name || !desc) {
                ret = -1;
                break;
            }
            printf("%d: %s (%s)\n", list[i], name, desc);
        }

        pcap_free_tstamp_types(list);
        return ret;
    }

    ret = pcap_set_snaplen(pcap, 1500);
    if (ret) {
        fprintf(stderr, "pcap_set_snaplen: %s\n", pcap_error(pcap, ret));
        return -1;
    }

    ret = pcap_set_promisc(pcap, 0);
    if (ret) {
        fprintf(stderr, "pcap_set_promisc: %s\n", pcap_error(pcap, ret));
        return -1;
    }

    ret = pcap_set_timeout(pcap, 100);
    if (ret) {
        fprintf(stderr, "pcap_set_timeout: %s\n", pcap_error(pcap, ret));
        return -1;
    }

    if (ts_type != NULL) {
        int type = pcap_tstamp_type_name_to_val(ts_type);
        if (type == PCAP_ERROR) {
            fprintf(stderr, "invalid type name (%s), check the list\n", optarg);
            return EINVAL;
        }
        ret = pcap_set_tstamp_type(pcap, type);
        if (ret != 0) {
            fprintf(stderr, "pcap_set_tstamp_type: %s\n", pcap_error(pcap, ret));
            return -1;
        }
    }

    ret = pcap_activate(pcap);
    if (ret) {
        /* error */
        if (ret < 0) {
            fprintf(stderr, "pcap_activate: %s\n", pcap_error(pcap, ret));
            return -1;
        }
        /* warning */
        if (ret > 0)
            fprintf(stderr, "pcap_activate: %s\n", pcap_error(pcap, ret));
    }

    snprintf(filter_exp, sizeof(filter_exp), "ip dst host %s and port %i", ip_dst, port);

    if (pcap_compile(pcap, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pcap));
        return -1;
    }
    if (pcap_setfilter(pcap, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(pcap));
        return -1;
    }

    /* Create socket */
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0) {
        perror("socket");
        return -11;
    }

    i = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&i, sizeof(i)) == -1) {
        perror("setsockopt SOL_SOCKET SO_REUSEADDR");
        close(fd);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    /* Bind */
    if (bind(fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        perror("bind");
        return -1;
    }

    if (ip_src) {
        /* Source-specific multicast */
        struct ip_mreq_source imr;
        imr.imr_multiaddr.s_addr = inet_addr(ip_dst);
        imr.imr_interface.s_addr = ip_src_addr.sin_addr.s_addr;
        imr.imr_sourceaddr.s_addr = inet_addr(ip_src);

        if (setsockopt(fd, IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, (char *)&imr, sizeof(imr)) < 0) {
            fprintf(stderr, "couldn't join multicast group (%m)\n");
            return 1;
        }
    } else {
        if (IN_MULTICAST(ntohl(inet_addr(ip_dst)))) {
            struct ip_mreqn mreq;
            mreq.imr_multiaddr.s_addr = inet_addr(ip_dst);
            mreq.imr_address.s_addr = INADDR_ANY;
            mreq.imr_ifindex = if_nametoindex(miface);
            if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*) &mreq, sizeof(mreq)) < 0){
                perror("setsockopt IPPROTO_IP IP_ADD_MEMBERSHIP");
                return -1;
            }
        }
    }

    if (opt_2022_6)
        pcap_loop(pcap, packet_count, got_packet_2022_6, (u_char*)pcap);
    if (opt_2110_video)
        pcap_loop(pcap, packet_count, got_packet_2110_video, (u_char*)pcap);
    else
        pcap_loop(pcap, packet_count, got_packet, (u_char*)pcap);

    close(fd);

    return 0;
}

