/*
 * server.c
 * CSC4200 — Program 2: TCP-Like Reliable Protocol over UDP
 *
 * Sprint 1: Three-Way Handshake
 *
 * Usage:  ./server -p <PORT> -s <LOGFILE>
 *
 * Right now this only handles the handshake. Data reception and
 * teardown will be added in Sprint 2 and Sprint 3.
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

/* ------------------------------------------------------------------ */
/* send_and_log – serialize a packet, send it to the given client     */
/* address, and log it.                                               */
/* ------------------------------------------------------------------ */
static int send_and_log(int sockfd, struct sockaddr_in *dest,
                        packet *pkt, FILE *logfp)
{
    uint8_t buf[MAX_PACKET];
    int     total = packet_serialize(pkt, buf);
    int     sent  = sendto(sockfd, buf, total, 0,
                           (struct sockaddr *)dest, sizeof(*dest));
    if (sent < 0) {
        perror("sendto");
        return -1;
    }
    log_packet(logfp, "SEND", pkt);
    return sent;
}

/* ------------------------------------------------------------------ */
/* recv_and_log – receive a UDP datagram, deserialize it, log it,     */
/* and store the sender's address.                                    */
/* ------------------------------------------------------------------ */
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
        fprintf(stderr, "server: bad packet received, ignoring\n");
        return -1;
    }

    log_packet(logfp, "RECV", pkt);
    return n;
}

/* ================================================================== */
/* main                                                               */
/* ================================================================== */
int main(int argc, char *argv[])
{
    int   port     = 0;
    char *log_path = NULL;
    int   opt;

    /* ---- parse command-line args ---- */
    while ((opt = getopt(argc, argv, "p:s:")) != -1) {
        switch (opt) {
            case 'p': port     = atoi(optarg);  break;
            case 's': log_path = optarg;        break;
            default:
                fprintf(stderr, "Usage: %s -p <PORT> -s <LOGFILE>\n",
                        argv[0]);
                return 1;
        }
    }

    if (port <= 0 || !log_path) {
        fprintf(stderr, "Usage: %s -p <PORT> -s <LOGFILE>\n", argv[0]);
        return 1;
    }

    /* ---- open the log file ---- */
    FILE *logfp = fopen(log_path, "w");
    if (!logfp) {
        perror("fopen log");
        return 1;
    }

    /* ---- create and bind the UDP socket ---- */
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        fclose(logfp);
        return 1;
    }

    /* allow quick restarts without "Address already in use" */
    int reuse = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port        = htons(port);

    if (bind(sockfd, (struct sockaddr *)&server_addr,
             sizeof(server_addr)) < 0) {
        perror("bind");
        close(sockfd);
        fclose(logfp);
        return 1;
    }

    printf("Listening on port %d.\n", port);

    /* ---- main loop: one iteration per client connection ---- */
    while (1) {

        struct sockaddr_in client_addr;
        packet             pkt;

        /* ========================================================== */
        /*  SPRINT 1 — Three-Way Handshake                            */
        /* ========================================================== */

        /* remove any leftover timeout so we block while idle */
        struct timeval no_timeout = {0, 0};
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
                   &no_timeout, sizeof(no_timeout));

        /* Step 1: wait for SYN (blocking – no timeout) */
        printf("Waiting for client...\n");
        while (1) {
            if (recv_and_log(sockfd, &pkt, logfp, &client_addr) < 0)
                continue;
            if (pkt.flags & FLAG_SYN)
                break;
        }

        uint32_t client_isn = pkt.seq_num;
        printf("SYN received from %s (ISN=%u)\n",
               inet_ntoa(client_addr.sin_addr), client_isn);

        /* Step 2: generate our own random ISN, send SYN|ACK */
        srand((unsigned)time(NULL) ^ getpid());
        uint32_t server_isn = (uint32_t)rand();

        packet syn_ack = make_packet(server_isn, client_isn + 1,
                                     FLAG_SYN | FLAG_ACK, NULL, 0);

        /* set a receive timeout for the ACK we're about to wait for */
        struct timeval tv = {TIMEOUT_SEC, TIMEOUT_USEC};
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        int handshake_ok = 0;

        for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
            send_and_log(sockfd, &client_addr, &syn_ack, logfp);

            /* Step 3: wait for ACK */
            packet reply;
            if (recv_and_log(sockfd, &reply, logfp, &client_addr) < 0) {
                printf("  Timeout waiting for ACK, retransmitting SYN|ACK"
                       " (%d/%d)\n", attempt + 1, MAX_RETRIES);
                continue;
            }

            /* might receive a retransmitted SYN — resend SYN|ACK */
            if (reply.flags & FLAG_SYN) {
                printf("  Got duplicate SYN, resending SYN|ACK\n");
                continue;
            }

            if ((reply.flags & FLAG_ACK) &&
                reply.ack_num == server_isn + 1) {
                handshake_ok = 1;
                break;
            }
        }

        if (!handshake_ok) {
            printf("Handshake failed, waiting for next client.\n");
            continue;
        }

        printf("Handshake complete.\n");

        /* ========================================================== */
        /*  TODO: Sprint 2 — Data Transfer goes here                  */
        /*  TODO: Sprint 3 — Teardown goes here                       */
        /* ========================================================== */

        printf("Waiting for next client...\n");
    }

    close(sockfd);
    fclose(logfp);
    return 0;
}
