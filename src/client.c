/*
 * client.c
 * CSC4200 — Program 2: TCP-Like Reliable Protocol over UDP
 *
 * Sprint 1: Three-Way Handshake
 *
 * Usage:  ./client -s <SERVER-IP> -p <PORT> -l <LOGFILE> -f <FILE>
 *
 * Right now this only performs the handshake. Data transfer and
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
#include <libgen.h>

/* ------------------------------------------------------------------ */
/* send_and_log – serialize a packet, send it via UDP, and log it.    */
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
/* recv_and_log – receive a UDP datagram, deserialize it, and log it. */
/* ------------------------------------------------------------------ */
static int recv_and_log(int sockfd, packet *pkt, FILE *logfp)
{
    uint8_t            buf[MAX_PACKET];
    struct sockaddr_in from;
    socklen_t          from_len = sizeof(from);

    int n = recvfrom(sockfd, buf, MAX_PACKET, 0,
                     (struct sockaddr *)&from, &from_len);
    if (n < 0) {
        return -1;
    }

    if (packet_deserialize(buf, n, pkt) < 0) {
        fprintf(stderr, "client: bad packet received, ignoring\n");
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
    char *server_ip  = NULL;
    int   port       = 0;
    char *log_path   = NULL;
    char *file_path  = NULL;
    int   opt;

    /* ---- parse command-line arguments ---- */
    while ((opt = getopt(argc, argv, "s:p:l:f:")) != -1) {
        switch (opt) {
            case 's': server_ip = optarg;          break;
            case 'p': port      = atoi(optarg);    break;
            case 'l': log_path  = optarg;          break;
            case 'f': file_path = optarg;          break;
            default:
                fprintf(stderr,
                        "Usage: %s -s <IP> -p <PORT> -l <LOG> -f <FILE>\n",
                        argv[0]);
                return 1;
        }
    }

    if (!server_ip || port <= 0 || !log_path || !file_path) {
        fprintf(stderr,
                "Usage: %s -s <IP> -p <PORT> -l <LOG> -f <FILE>\n",
                argv[0]);
        return 1;
    }

    /* ---- open log file ---- */
    FILE *logfp = fopen(log_path, "w");
    if (!logfp) {
        perror("fopen log");
        return 1;
    }

    /* ---- create UDP socket ---- */
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        fclose(logfp);
        return 1;
    }

    /* set a receive timeout so recvfrom() doesn't block forever */
    struct timeval tv;
    tv.tv_sec  = TIMEOUT_SEC;
    tv.tv_usec = TIMEOUT_USEC;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* ---- fill in the server address struct ---- */
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(port);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);

    /* ============================================================== */
    /*  SPRINT 1 — Three-Way Handshake                                */
    /* ============================================================== */

    /* pick a random initial sequence number */
    srand((unsigned)time(NULL) ^ getpid());
    uint32_t client_isn = (uint32_t)rand();

    printf("Starting handshake with %s:%d ...\n", server_ip, port);

    /* Step 1: send SYN */
    packet syn = make_packet(client_isn, 0, FLAG_SYN, NULL, 0);

    uint32_t server_isn = 0;
    int      connected  = 0;

    for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
        send_and_log(sockfd, &server_addr, &syn, logfp);

        /* Step 2: wait for SYN|ACK */
        packet reply;
        if (recv_and_log(sockfd, &reply, logfp) < 0) {
            printf("  Timeout waiting for SYN|ACK, retrying (%d/%d)\n",
                   attempt + 1, MAX_RETRIES);
            continue;
        }

        /* validate the SYN|ACK */
        if ((reply.flags & (FLAG_SYN | FLAG_ACK)) != (FLAG_SYN | FLAG_ACK)) {
            printf("  Unexpected flags, retrying\n");
            continue;
        }
        if (reply.ack_num != client_isn + 1) {
            printf("  Bad ack_num in SYN|ACK, retrying\n");
            continue;
        }

        server_isn = reply.seq_num;
        connected  = 1;
        break;
    }

    if (!connected) {
        fprintf(stderr, "Handshake failed after %d retries.\n",
                MAX_RETRIES);
        close(sockfd);
        fclose(logfp);
        return 1;
    }

    /* Step 3: send ACK */
    packet ack = make_packet(client_isn + 1, server_isn + 1,
                             FLAG_ACK, NULL, 0);
    send_and_log(sockfd, &server_addr, &ack, logfp);

    printf("Handshake complete.\n");

    /* ============================================================== */
    /*  TODO: Sprint 2 — Data Transfer goes here                      */
    /*  TODO: Sprint 3 — Teardown goes here                           */
    /* ============================================================== */

    close(sockfd);
    fclose(logfp);
    return 0;
}
