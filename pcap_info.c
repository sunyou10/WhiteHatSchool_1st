#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
/* Ethernet Header */
struct ethheader
{
    unsigned char ether_dhost[6];
    unsigned char ether_shost[6];
    unsigned short ether_type;
};

/* IP Header */
struct ipheader
{
    unsigned char       iph_ihl:4,
                        iph_ver:4;
    unsigned char       iph_tos;
    unsigned short int  iph_len;
    unsigned short int  iph_flag:3,
                        iph_offset:13;
    unsigned char       iph_ttl;
    unsigned char       iph_protocol;
    unsigned short int  iph_chksum;
    struct in_addr      iph_sourceip;
    struct in_addr      iph_destip;
};

/* TCP Header */
struct tcpheader {
    unsigned short tcp_sport;
    unsigned short tcp_dport;
    unsigned int   tcp_seq;
    unsigned int   tcp_ack;
    unsigned char  tcp_offx2;
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    unsigned char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    unsigned short tcp_win;
    unsigned short tcp_sum;
    unsigned short tcp_urp;
};

/* Psuedo TCP header */
struct pseudo_tcp
{
        unsigned saddr, daddr;
        unsigned char mbz;
        unsigned char ptcl;
        unsigned short tcpl;
        struct tcpheader tcp;
        char payload[1500];
};


void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) 
{
    printf("Packet captured!\n");
    struct ethheader *eth = (struct ethheader *) packet;

    if (ntohs(eth->ether_type) == 0x0800){
        struct ipheader *ip = (struct ipheader *) (packet + sizeof(struct ethheader));
        struct tcpheader *tcp = (struct tcpheader *) (packet + sizeof(struct ethheader)+sizeof(struct ipheader));

        /* 송신MAC과 수신MAC 출력 */
        printf("Ethernet Address(MAC)\n");
        printf("        From: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                   eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
        printf("        To: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                   eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
        
        /* 송신IP와 수신IP 출력 */
        printf("IP Address\n");
        printf("        From: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("        To: %s\n", inet_ntoa(ip->iph_destip));

        printf("    Protocol: TCP\n");

        /* TCP 헤더 출력 */
        printf("TCP Port\n");
        printf("        From: %u\n", ntohs(tcp->tcp_sport));
        printf("        To: %u\n", ntohs(tcp->tcp_dport));

        /* 메시지 출력 */
        char payload[1500];
        int payload_length = header -> len - (sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct tcpheader));

        memcpy(payload, packet + sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct tcpheader), payload_length);

        printf("Message: ");
        for(int i = 0; i < payload_length; i++) {
            printf("%c", payload[i]);
            if((i + 1) % 16 == 0)
                printf("\n");
        }
        printf("\n");
    }

}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE]; // 오류메시지 배열에 저장
    struct bpf_program fp;
    char filter_exp[] = "tcp"; // 필터링 할 프로토콜 == tcp
    bpf_u_int32 net;

    // ens33로 네트워크 인터페이스 열기
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

    // filer_exp 컴파일
    pcap_compile(handle, &fp, filter_exp, 0, net);

    // 예외 처리
    if(pcap_setfilter(handle, &fp)!=0) {
        pcap_perror(handle, "Error: ");
        exit(EXIT_FAILURE);
    }

    // 패킷 캡처 및 처리
    if (pcap_loop(handle, 0, got_packet, NULL) < 0) {
        printf("Error in pcap_loop()\n");
        return 1;
    }

    pcap_close(handle);

    return 0;
}
