/*
 * client.c
 * CSC4200 — Program 2: TCP-Like Reliable Protocol over UDP
 *
 * Usage:  ./client -s <SERVER-IP> -p <PORT> -l <LOGFILE> -f <FILE>
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

// SPRINT 1 EXPLANATION — Sending and UDP:
//
//   Unlike TCP where you use send(), for UDP we use sendto() because UDP is
//   connectionless. Every packet must explicitly specify the destination address.
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

// SPRINT 1 EXPLANATION — Receiving over UDP:
//
//   Similarly, we use recvfrom() to receive UDP datagrams, which fills
//   in the source address of whoever sent it. If a packet is malformed,
//   we ignore it, unlike TCP which provides an ordered byte stream.
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

int main(int argc, char *argv[])
{
    char *server_ip  = "10.128.0.2";   /* default: server VM    */
    int   port       = 5000;            /* default port          */
    char *log_path   = "client.log";    /* default log file      */
    char *file_path  = "testfile.txt";  /* default file to send  */
    int   opt;

    while ((opt = getopt(argc, argv, "s:p:l:f:")) != -1) {
        switch (opt) {
            case 's': server_ip = optarg;          break;
            case 'p': port      = atoi(optarg);    break;
            case 'l': log_path  = optarg;          break;
            case 'f': file_path = optarg;          break;
            default:
                fprintf(stderr,
                        "Usage: %s [-s <IP>] [-p <PORT>] [-l <LOG>] [-f <FILE>]\n",
                        argv[0]);
                return 1;
        }
    }

    printf("Using server=%s, port=%d, log=%s, file=%s\n",
           server_ip, port, log_path, file_path);

    FILE *logfp = fopen(log_path, "w");
    if (!logfp) {
        perror("fopen log");
        return 1;
    }

    // SPRINT 1 EXPLANATION — socket() for UDP:
    //
    //   SOCK_DGRAM creates a User Datagram Protocol (UDP) socket.
    //   Unlike TCP's SOCK_STREAM, UDP gives us no reliability, ordering,
    //   or duplicate detection. We must implement those features manually.
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        fclose(logfp);
        return 1;
    }

    // SPRINT 2 EXPLANATION — RCVTIMEO timeout:
    //
    //   To implement packet retransmissions, we set SO_RCVTIMEO on the socket. This ensures
    //   that if an ACK doesn't arrive in time, recvfrom() will unblock with a timeout
    //   error, allowing our loop to trigger a retransmission.
    struct timeval tv;
    tv.tv_sec  = TIMEOUT_SEC;
    tv.tv_usec = TIMEOUT_USEC;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(port);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);


    
    // SPRINT 1 EXPLANATION — ISN generation:
    //
    //   We use srand() to generate a random Initial Sequence Number (ISN).
    //   This prevents spoofing and "ghost packets" from a previous connection
    //   teardown from colliding with a new active connection.
    srand((unsigned)time(NULL) ^ getpid());
    uint32_t client_isn = (uint32_t)rand();

    printf("Starting handshake with %s:%d ...\n", server_ip, port);

    packet syn = make_packet(client_isn, 0, FLAG_SYN, NULL, 0);

    uint32_t server_isn = 0;
    int      connected  = 0;

    // SPRINT 1 EXPLANATION — Reliability Retransmission Loop:
    //
    //   Because UDP is unreliable, the SYN or the server's SYN-ACK could be dropped.
    //   Looping up to MAX_RETRIES enforces successful connection progression in userspace.
    for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
        send_and_log(sockfd, &server_addr, &syn, logfp);

        packet reply;
        if (recv_and_log(sockfd, &reply, logfp) < 0) {
            printf("  Timeout waiting for SYN|ACK, retrying (%d/%d)\n",
                   attempt + 1, MAX_RETRIES);
            continue;
        }

        if ((reply.flags & (FLAG_SYN | FLAG_ACK)) != (FLAG_SYN | FLAG_ACK)) {
            continue;
        }
        if (reply.ack_num != client_isn + 1) {
            continue;
        }

        server_isn = reply.seq_num;
        connected  = 1;
        break;
    }

    if (!connected) {
        fprintf(stderr, "Handshake failed after %d retries.\n", MAX_RETRIES);
        close(sockfd);
        fclose(logfp);
        return 1;
    }

    packet ack = make_packet(client_isn + 1, server_isn + 1, FLAG_ACK, NULL, 0);
    send_and_log(sockfd, &server_addr, &ack, logfp);

    printf("Handshake complete.\n");



    FILE *infp = fopen(file_path, "rb");
    if (!infp) {
        perror("fopen file");
        close(sockfd);
        fclose(logfp);
        return 1;
    }

    uint32_t current_seq = client_isn + 1;
    int is_first_packet = 1;
    
    char file_copy[256];
    strncpy(file_copy, file_path, sizeof(file_copy) - 1);
    file_copy[sizeof(file_copy) - 1] = '\0';
    char *base_name = basename(file_copy);

    printf("Starting file transfer of %s ...\n", base_name);

    while (1) {
        uint8_t payload_buf[MAX_PAYLOAD];
        uint32_t payload_len = 0;

        // SPRINT 2 EXPLANATION — First packet FILENAME embed:
        //
        //   The first payload over the line acts as a header mapping its original baseline string name.
        if (is_first_packet) {
            int prefix_len = snprintf((char *)payload_buf, MAX_PAYLOAD, "FILENAME:%s", base_name) + 1;
            payload_len += prefix_len;

            size_t bytes_read = fread(payload_buf + prefix_len, 1, MAX_PAYLOAD - prefix_len, infp);
            payload_len += bytes_read;
            is_first_packet = 0;
        } else {
            size_t bytes_read = fread(payload_buf, 1, MAX_PAYLOAD, infp);
            payload_len = bytes_read;
        }

        if (payload_len == 0) {
            break;
        }

        packet pkt = make_packet(current_seq, 0, 0, payload_buf, payload_len);
        int acked = 0;

        // SPRINT 2 EXPLANATION — Stop-and-Wait Data Transmission:
        //
        //   For reliable delivery, we wait for an explicit ACK containing the exact SEQ offset mapped 
        //   dynamically before generating and transmitting the next block.
        for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
            send_and_log(sockfd, &server_addr, &pkt, logfp);

            packet reply;
            if (recv_and_log(sockfd, &reply, logfp) < 0) {
                printf("  Timeout waiting for ACK, retransmitting (%d/%d)\n", attempt + 1, MAX_RETRIES);
                continue;
            }

            if ((reply.flags & FLAG_ACK) && reply.ack_num == current_seq + payload_len) {
                current_seq += payload_len;
                acked = 1;
                break;
            }
        }

        if (!acked) {
            fprintf(stderr, "Transfer failed after %d retries.\n", MAX_RETRIES);
            fclose(infp);
            close(sockfd);
            fclose(logfp);
            return 1;
        }
    }

    printf("File transfer complete. Sent %u bytes of reliable data.\n", current_seq - (client_isn + 1));
    fclose(infp);



    // SPRINT 3 EXPLANATION — FIN teardown logic:
    //
    //   At the end of reliable transfer, one side must broadcast a FIN flag packet.
    //   We repeat the standard retransmission loop waiting specifically for both FIN|ACK flags on the response payload.
    printf("Starting connection teardown...\n");
    packet fin_pkt = make_packet(current_seq, 0, FLAG_FIN, NULL, 0);
    int fin_acked = 0;

    for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
        send_and_log(sockfd, &server_addr, &fin_pkt, logfp);

        packet reply;
        if (recv_and_log(sockfd, &reply, logfp) < 0) {
            printf("  Timeout waiting for FIN|ACK, retransmitting FIN (%d/%d)\n", attempt + 1, MAX_RETRIES);
            continue;
        }

        if ((reply.flags & (FLAG_FIN | FLAG_ACK)) == (FLAG_FIN | FLAG_ACK)) {
            if (reply.ack_num == current_seq + 1) {
                fin_acked = 1;
                break;
            }
        }
    }

    if (!fin_acked) {
        fprintf(stderr, "Teardown failed after %d retries.\n", MAX_RETRIES);
    } else {
        printf("Connection closed cleanly.\n");
    }

    close(sockfd);
    fclose(logfp);
    return 0;
}
