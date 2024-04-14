#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
// #include <linux/netfilter.h> /* for NF_ACCEPT */
#include <linux/types.h>
// #include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NF_ACCEPT 1
#define NF_DROP 0

struct tcphdr *tcp_header;
struct iphdr *ip_header;

char **domains;
int count = 0;
int temp_id = 0;

// char *target_url;

void dump(unsigned char *buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        buf[i] = (buf[i] >= 32 && buf[i] <= 128) ? buf[i] : '.';
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

/* returns packet id */
static u_int32_t print_pkt(struct nfq_data *tb) {
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark, ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol),
               ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen - 1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen - 1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0) {
        ip_header = (struct iphdr *)data;

        // Check if the packet is using TCP and TCP port is 80 (HTTP)
        if (ip_header->protocol == IPPROTO_TCP) {
            tcp_header = (struct tcphdr *)(data + ip_header->ihl * 4);
            if (ntohs(tcp_header->dest) == 80) {
                char *http_data =
                    (char *)(data + ip_header->ihl * 4 + tcp_header->doff * 4);

                char *host_start = strstr(http_data, "Host: ");
                if (host_start != NULL) {
                    host_start += strlen("Host: ");
                    char *host_end = strchr(host_start, '\r');
                    if (host_end != NULL) {
                        char host[256];
                        strncpy(host, host_start, host_end - host_start);
                        host[host_end - host_start] = '\0';

                        for (int i = 0; i < count; i++) {
                            if (strcmp(host, domains[i]) == 0) {
                                temp_id = id;
                                return 0;
                            }
                        }
                    }
                }
            }
        }
    }
    fputc('\n', stdout);
    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data1) {
    u_int32_t id = print_pkt(nfa);
    printf("entering callback\n");

    if (id == 0)
        return nfq_set_verdict(qh, temp_id, NF_DROP, 0, NULL);

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__((aligned));

    FILE *file = fopen(argv[1], "r");
    if (file == NULL) {
        printf("파일을 열 수 없습니다.\n");
        return 1;
    }

    domains = (char **)malloc(1000000 * sizeof(char *));
    if (domains == NULL) {
        printf("메모리 할당 실패\n");
        fclose(file);
        return 1;
    }

    char line[256];
    while (fgets(line, sizeof(line), file) && count < 1000000) {
        char *token = strchr(line, ',');
        if (token != NULL) {
            token++;
            domains[count] = (char *)malloc(100 * sizeof(char));
            if (domains[count] == NULL) {
                printf("메모리 할당 실패\n");
                break;
            }
            strcpy(domains[count], token);
            strtok(domains[count], "\n");
            count++;
        }
    }

    fclose(file);

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored.
         * nfq_nlmsg_verdict_putPlease, see the doxygen documentation of this
         * library on how to improve this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    for (int i = 0; i < count; i++) {
        free(domains[i]);
    }
    free(domains);

    exit(0);
}
