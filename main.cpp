#include <iostream>
#include <cstdint>
#include <cstring>
#include <pcap/pcap.h>

#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <getopt.h>

#define VERSION "V0.0.1"


using namespace std;

pcap_dumper_t *file_handler = NULL;
uint32_t maxip = 0;
uint8_t flag = 0;

void printHelp()
{
    cout << "Packet generate tools" << endl;
    cout << "Usage: GenPacket [-v] [-h] [-r <read pcap file>] [-b <bpf rules>] [-w <new pcap file>]" << endl;
    cout << "\t-v version" << endl;
    cout << "\t-h help" << endl;
    cout << "\t-r read pcap file path" << endl;
    cout << "\t-b packet filter rules" << endl;
    cout << "\t-w save new pcap file path" << endl;
    cout << "Author: FengJun" << endl;
}

void packet_pro(u_char *user, const struct pcap_pkthdr *hdr, const u_char *bytes)
{
    struct timeval ts;
    struct pcap_pkthdr n_hdr;
    memset(&n_hdr, 0, sizeof(pcap_pkthdr));
    gettimeofday(&ts, NULL);

    /* gen new hdr */
    n_hdr.ts = ts;
    n_hdr.caplen = hdr->caplen;
    n_hdr.len = hdr->len;

    /* modify tuple saddr/sp/daddr/dp, first time donot modify */
    if (flag != 0)
    {
        struct ip *iphdr = (struct ip *) (bytes + 14);
        struct tcphdr *tcp = (struct tcphdr *) (bytes + 14 + 4 * iphdr->ip_hl);

        if ( 80 == ntohs(tcp->th_sport))
        {
            uint32_t *ipaddr = &iphdr->ip_dst.s_addr;
            *ipaddr = htonl((ntohl(*ipaddr) + 1) % maxip);

            uint16_t *port = (uint16_t *) &(tcp->th_dport);
            *port = htons(((ntohs(*port) + 1) % (65535 - 50000)) + 50000);
        }
        else if ( 80 == ntohs(tcp->th_dport))
        {
            u_int *ipaddr = &iphdr->ip_src.s_addr;
            *ipaddr = htonl((ntohl(*ipaddr) + 1) % maxip);

            uint16_t *port = (uint16_t *) &(tcp->th_sport);
            *port = htons(((ntohs(*port) + 1) % (65535 - 50000)) + 50000);
        }
        else
        {
            return;
        }
    }

    pcap_dump((u_char *)file_handler, hdr, bytes);
}

int main(int argc, char *argv[])
{
    int ret;
    int times = 1;
    char open_filename[256] = {0};
    char save_filename[256] = {0};
    char bpf_rule[512] = {0};
    bool isBPF = false;
    bool isOpen = false, isSave = false;

    extern char *optarg;
    extern int optind, optopt;
    /* read arguments */
    while ((ret = getopt(argc, argv, "r:b:w:t:hv")) != -1)
    {
        switch ( ret )
        {
            case 'r':
                isOpen = true;
                snprintf(open_filename, sizeof(open_filename), "%s", optarg);
                break;
            case 'b':
                {
                    isBPF = true;
                    int offset = 0, index = 0;
                    offset = snprintf(bpf_rule, sizeof(bpf_rule), "%s", optarg);
                    while ( argv[optind + index][0] != '-' )
                    {
                        offset += snprintf(bpf_rule + offset, sizeof(bpf_rule) - offset, " %s", argv[optind + index]);
                        index++;
                    }
                }
                break;
            case 'w':
                isSave = true;
                snprintf(save_filename, sizeof(save_filename), "%s", optarg);
                break;
            case 't':
                times = strtol(optarg, NULL, 10);
                break;
            case 'h':
                printHelp();
                return 0;
            case 'v':
                cout << "GenPacket Tools:" << VERSION << endl;
                return 0;
            default:
                cout << "Options error!" << endl;
                return -1;
        }
    }
    if (!isOpen || !isSave)
    {
        cout << "File Options error!" << endl;
        return -1;
    }

#if 0
    cout << "Open file: " << open_filename << endl;
    cout << "Save file: " << save_filename << endl;
    cout << "BPF Rule: " << bpf_rule << endl;
    cout << "Times: " << times << endl;
#endif

    /* initialize max ip */
    inet_pton(AF_INET, "255.255.255.255", &maxip);

    /*initialize write pcap files*/
    pcap_t *save_file = pcap_open_dead(DLT_EN10MB, 2000);
    if (save_file == NULL)
    {
        cout << "Create pcap save file error!" << endl;
        return -1;
    }
    FILE *fp = fopen(save_filename, "ab+");
    if (fp == NULL)
    {
        cout << "Create file " << save_filename << " failed!" << endl;
    }

    file_handler = pcap_dump_fopen(save_file, fp);
    if (file_handler == NULL)
    {
        cout << "Open dump file error!" << endl;
        return -1;
    }

    /* ready to read pcap file */
    for (int i = 0; i < times; i++)
    {
        char errbuff[PCAP_ERRBUF_SIZE] = {0};
        pcap_t *cap_handler = pcap_open_offline(open_filename, errbuff);
        if ( cap_handler == NULL )
        {
            cout << "Open file " << open_filename << " failed!" << endl;
            return -1;
        }

        int link = pcap_datalink(cap_handler);
        if ( link != DLT_EN10MB )
        {
            cout << "not ethernet link!" << endl;
            return -1;
        }

        /* gen bpf */
        if (isBPF)
        {
            struct bpf_program fp;
            if ( pcap_compile(cap_handler, &fp, bpf_rule, 1, 0) == -1 )
            {
                cout << "Bpf error!" << endl;
                return -1;
            }

            if ( pcap_setfilter(cap_handler, &fp) == -1 )
            {
                cout << "Set Bpf error!" << endl;
                return -1;
            }

            pcap_loop(cap_handler, -1, (pcap_handler) packet_pro, 0);

            pcap_close(cap_handler);
            pcap_freecode(&fp);
        }
        else
        {
            pcap_loop(cap_handler, -1, (pcap_handler) packet_pro, 0);
            pcap_close(cap_handler);
        }
        flag = 1;
    }
    pcap_close(save_file);
    fclose(fp);
    return 0;
}