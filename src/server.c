/*
 * server.c
 * CSC4200 — Program 2: TCP-Like Reliable Protocol over UDP
 *
 * Usage:  ./server -p <PORT> -s <LOGFILE>
 */

#include "protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>

// SPRINT 1 EXPLANATION — send_and_log:
//
//   Uses sendto() for connectionless transmission because UDP sockets 
//   do not maintain an active outbound connection tracking IP addresses natively.
static int send_and_log(int sockfd, struct sockaddr_in *dest,
                        packet *pkt, FILE *logfp)
{
    uint8_t buf[MAX_PACKET];
    int     total = packet_serialize(pkt, buf);
    int     sent  = sendto(sockfd, buf, total, 0,
                           (struct sockaddr *)dest, sizeof(*dest));
    if (sent < 0) {
        return -1;
    }
    log_packet(logfp, "SEND", pkt);
    return sent;
}

// SPRINT 1 EXPLANATION — recv_and_log:
//
//   recvfrom() automatically extracts the physical IP address and origin port 
//   of whoever dispatched the packet on the other end to the dest buffer.
static int recv_and_log(int sockfd, packet *pkt, FILE *logfp,
                        struct sockaddr_in *from)
{
    uint8_t   buf[MAX_PACKET];
    socklen_t from_len = sizeof(*from);

    int n = recvfrom(sockfd, buf, MAX_PACKET, 0,
                     (struct sockaddr *)from, &from_len);
    if (n < 0) {
        return -1;
    }

    if (packet_deserialize(buf, n, pkt) < 0) {
        return -1;
    }

    log_packet(logfp, "RECV", pkt);
    return n;
}

int main(int argc, char *argv[])
{
    int   port     = 5000;
    char *log_path = "server.log";
    int   opt;

    while ((opt = getopt(argc, argv, "p:s:")) != -1) {
        switch (opt) {
            case 'p': port     = atoi(optarg);  break;
            case 's': log_path = optarg;        break;
            default: return 1;
        }
    }

    FILE *logfp = fopen(log_path, "w");
    if (!logfp) return 1;

    // SPRINT 1 EXPLANATION — UDP socket instantiation:
    //
    //   Creating an endpoint using SOCK_DGRAM establishes connectionless UDP 
    //   networking properties rather than reliable TCP streams.
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return 1;

    int reuse = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port        = htons(port);

    // SPRINT 1 EXPLANATION — bind():
    //
    //   We explicitly bind the socket to the port so that incoming connection 
    //   packets get correctly routed to this running server instance by the OS.
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        return 1;
    }

    printf("Listening on port %d.\n", port);

    while (1) {
        struct sockaddr_in client_addr;
        packet             pkt;



        // SPRINT 1 EXPLANATION — Non-blocking wait cycle:
        //
        //   Disabling the SO_RCVTIMEO flag effectively turns the main wait cycle back 
        //   into infinite blocking mode until it detects incoming SYN requests naturally.
        struct timeval no_timeout = {0, 0};
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &no_timeout, sizeof(no_timeout));

        printf("Waiting for client...\n");
        while (1) {
            if (recv_and_log(sockfd, &pkt, logfp, &client_addr) < 0) continue;
            if (pkt.flags & FLAG_SYN) break;
        }

        uint32_t client_isn = pkt.seq_num;
        printf("SYN received from %s (ISN=%u)\n", inet_ntoa(client_addr.sin_addr), client_isn);

        srand((unsigned)time(NULL) ^ getpid());
        uint32_t server_isn = (uint32_t)rand();

        packet syn_ack = make_packet(server_isn, client_isn + 1, FLAG_SYN | FLAG_ACK, NULL, 0);

        struct timeval tv = {TIMEOUT_SEC, TIMEOUT_USEC};
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        int handshake_ok = 0;

        for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
            send_and_log(sockfd, &client_addr, &syn_ack, logfp);

            packet reply;
            if (recv_and_log(sockfd, &reply, logfp, &client_addr) < 0) {
                continue;
            }

            if (reply.flags & FLAG_SYN) continue;

            if ((reply.flags & FLAG_ACK) && reply.ack_num == server_isn + 1) {
                handshake_ok = 1;
                break;
            }
        }

        if (!handshake_ok) continue;

        printf("Handshake complete.\n");


        
        uint32_t expected_seq = client_isn + 1;
        FILE *outfp = NULL;

        while (1) {
            if (recv_and_log(sockfd, &pkt, logfp, &client_addr) < 0) {
                continue; 
            }

            if (pkt.flags & FLAG_FIN) {
                break;
            }

            // SPRINT 2 EXPLANATION — Out-of-order duplicate packet detection:
            //
            //   If the stream receives an out of order loop sequence, it dynamically pushes a duplicate 
            //   ACK natively to prompt the sender to resend the gap.
            if (pkt.seq_num != expected_seq) {
                packet dup_ack = make_packet(0, expected_seq, FLAG_ACK, NULL, 0);
                send_and_log(sockfd, &client_addr, &dup_ack, logfp);
                continue;
            }

            if (pkt.payload_len > 0) {
                if (!outfp) {
                    if (strncmp((char *)pkt.payload, "FILENAME:", 9) == 0) {
                        char *name = (char *)pkt.payload + 9;
                        int name_len = strlen(name);

                        char out_name[256];
                        snprintf(out_name, sizeof(out_name), "received_%s", name);
                        outfp = fopen(out_name, "wb");
                        if (outfp) {
                            printf("Receiving file -> %s\n", out_name);
                            int prefix_len = 9 + name_len + 1; 
                            if (pkt.payload_len > (uint32_t)prefix_len) {
                                fwrite(pkt.payload + prefix_len, 1, pkt.payload_len - prefix_len, outfp);
                                fflush(outfp);
                            }
                        }
                    }
                } else {
                    fwrite(pkt.payload, 1, pkt.payload_len, outfp);
                    fflush(outfp);
                }
            }

            expected_seq += pkt.payload_len;

            packet expected_ack = make_packet(0, expected_seq, FLAG_ACK, NULL, 0);
            send_and_log(sockfd, &client_addr, &expected_ack, logfp);
        }

        if (outfp) {
            fclose(outfp);
        }



        // SPRINT 3 EXPLANATION — Graceful Teardown Server Logic:
        //
        //   When the user sends the FIN trigger marking closure, the file pointer handles its flush and
        //   we explicitly broadcast the FIN|ACK flagged confirmation offset before restarting 
        //   the continuous socket timeout boundaries infinitely to wait natively for another request. 
        printf("Interaction with %s completed.\n", inet_ntoa(client_addr.sin_addr));

        packet fin_ack = make_packet(0, pkt.seq_num + 1, FLAG_FIN | FLAG_ACK, NULL, 0);
        send_and_log(sockfd, &client_addr, &fin_ack, logfp);

        struct timeval no_timeout_again = {0, 0};
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &no_timeout_again, sizeof(no_timeout_again));

        printf("Waiting for next client...\n");
    }

    close(sockfd);
    fclose(logfp);
    return 0;
}
