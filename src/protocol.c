/*
 * protocol.c
 * CSC4200 — Program 2: TCP-Like Reliable Protocol over UDP
 *
 * Implements the shared helper functions that both the client
 * and server rely on for building, serializing, deserializing,
 * and logging packets.
 */

#include "protocol.h"

#include <string.h>
#include <time.h>
#include <arpa/inet.h>   /* htonl / ntohl */

/* ------------------------------------------------------------------ */
/* timestamp – writes the current local time into buf as               */
/*             "YYYY-MM-DD-HH-MM-SS"                                  */
/* ------------------------------------------------------------------ */
void timestamp(char *buf, size_t len)
{
    time_t     now;
    struct tm *t;

    time(&now);
    t = localtime(&now);

    /* strftime does the heavy lifting here */
    strftime(buf, len, "%Y-%m-%d-%H-%M-%S", t);
}

/* ------------------------------------------------------------------ */
/* packet_serialize – copy each field into buf in network byte order.  */
/* We deliberately avoid casting the struct to bytes directly because  */
/* the compiler might add padding between fields on some platforms.    */
/* ------------------------------------------------------------------ */
int packet_serialize(packet *pkt, uint8_t *buf)
{
    uint32_t net_val;
    int      offset = 0;

    /* sequence number (4 bytes) */
    net_val = htonl(pkt->seq_num);
    memcpy(buf + offset, &net_val, 4);
    offset += 4;

    /* acknowledgment number (4 bytes) */
    net_val = htonl(pkt->ack_num);
    memcpy(buf + offset, &net_val, 4);
    offset += 4;

    /* flags (4 bytes – only low 3 bits matter) */
    net_val = htonl(pkt->flags);
    memcpy(buf + offset, &net_val, 4);
    offset += 4;

    /* payload length (4 bytes) */
    net_val = htonl(pkt->payload_len);
    memcpy(buf + offset, &net_val, 4);
    offset += 4;

    /* payload data (variable length) */
    if (pkt->payload_len > 0) {
        memcpy(buf + offset, pkt->payload, pkt->payload_len);
        offset += pkt->payload_len;
    }

    return offset;   /* HEADER_SIZE + payload_len */
}

/* ------------------------------------------------------------------ */
/* packet_deserialize – rebuild a packet struct from a raw byte buffer */
/* received via recvfrom().  Returns 0 on success, -1 on failure.     */
/* ------------------------------------------------------------------ */
int packet_deserialize(uint8_t *buf, int len, packet *pkt)
{
    uint32_t net_val;

    /* need at least the 16-byte header to do anything useful */
    if (len < HEADER_SIZE) {
        return -1;
    }

    /* zero out the struct first so stale payload bytes don't linger */
    memset(pkt, 0, sizeof(packet));

    int offset = 0;

    /* sequence number */
    memcpy(&net_val, buf + offset, 4);
    pkt->seq_num = ntohl(net_val);
    offset += 4;

    /* acknowledgment number */
    memcpy(&net_val, buf + offset, 4);
    pkt->ack_num = ntohl(net_val);
    offset += 4;

    /* flags */
    memcpy(&net_val, buf + offset, 4);
    pkt->flags = ntohl(net_val);
    offset += 4;

    /* payload length */
    memcpy(&net_val, buf + offset, 4);
    pkt->payload_len = ntohl(net_val);
    offset += 4;

    /* sanity check – don't read past the data we actually received */
    if (pkt->payload_len > MAX_PAYLOAD) {
        return -1;
    }

    /* copy the payload bytes */
    if (pkt->payload_len > 0) {
        uint32_t available = (uint32_t)(len - HEADER_SIZE);
        uint32_t to_copy   = (pkt->payload_len < available)
                             ? pkt->payload_len : available;
        memcpy(pkt->payload, buf + offset, to_copy);
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* make_packet – convenience function to build a packet struct in one  */
/*               call instead of setting fields individually.          */
/* ------------------------------------------------------------------ */
packet make_packet(uint32_t seq, uint32_t ack, uint32_t flags,
                   uint8_t *data, uint32_t data_len)
{
    packet pkt;
    memset(&pkt, 0, sizeof(packet));

    pkt.seq_num     = seq;
    pkt.ack_num     = ack;
    pkt.flags       = flags;
    pkt.payload_len = data_len;

    if (data != NULL && data_len > 0) {
        memcpy(pkt.payload, data, data_len);
    }

    return pkt;
}

/* ------------------------------------------------------------------ */
/* log_packet – writes one log line in the required format:            */
/*   [YYYY-MM-DD-HH-MM-SS] SEND|RECV SEQ=<n> ACK=<n> [ACK] [SYN]    */
/*   [FIN] [LEN=<n>]                                                   */
/* Flushes immediately so log output is never buffered.                */
/* ------------------------------------------------------------------ */
void log_packet(FILE *logfp, const char *direction, packet *pkt)
{
    char ts[64];
    timestamp(ts, sizeof(ts));

    fprintf(logfp, "[%s] %s SEQ=%u ACK=%u",
            ts, direction, pkt->seq_num, pkt->ack_num);

    /* print flag tokens only when the corresponding bit is set */
    if (pkt->flags & FLAG_ACK) fprintf(logfp, " ACK");
    if (pkt->flags & FLAG_SYN) fprintf(logfp, " SYN");
    if (pkt->flags & FLAG_FIN) fprintf(logfp, " FIN");

    if (pkt->payload_len > 0) {
        fprintf(logfp, " LEN=%u", pkt->payload_len);
    }

    fprintf(logfp, "\n");
    fflush(logfp);
}
