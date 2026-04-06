/*
 * protocol.h
 * CSC4200 — Program 2: TCP-Like Reliable Protocol over UDP
 *
 * This header defines the packet structure and constants for the
 * custom reliability protocol you will implement.
 *
 * DO NOT change field names, sizes, or the HEADER_SIZE constant.
 * Your serialization and deserialization must match this layout exactly.
 *
 * Packet Wire Format (all fields big-endian / network byte order):
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     Sequence Number  (32 bits)                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                  Acknowledgment Number (32 bits)              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                   Not Used (29 bits)                    |A|S|F|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Payload Length (32 bits)                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Payload (variable)                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Flag bits (low 3 bits of the flags field):
 *   Bit 0 (F) — FIN  : No more data from sender; initiate teardown
 *   Bit 1 (S) — SYN  : Synchronize sequence numbers (handshake)
 *   Bit 2 (A) — ACK  : Acknowledgment Number field is valid
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stdio.h>

/* ——— Wire‑format constants ————————————————————————— */
#define HEADER_SIZE   16          /* 4 x 32-bit fields                  */
#define MAX_PAYLOAD   512         /* bytes of file data per packet      */
#define MAX_PACKET    (HEADER_SIZE + MAX_PAYLOAD)

/* ——— Retry / timeout tuning ———————————————————————— */
#define MAX_RETRIES   10
#define TIMEOUT_SEC   1
#define TIMEOUT_USEC  0

/* ——— Flag bit masks ———————————————————————————————— */
#define FLAG_FIN      0x1         /* bit 0 – finished sending           */
#define FLAG_SYN      0x2         /* bit 1 – synchronize seq nums       */
#define FLAG_ACK      0x4         /* bit 2 – ack field is valid         */

/* ——— Packet structure (host representation) ———————— */
typedef struct {
    uint32_t seq_num;             /* sequence number                    */
    uint32_t ack_num;             /* acknowledgment number              */
    uint32_t flags;               /* only low 3 bits are used           */
    uint32_t payload_len;         /* number of payload bytes that follow*/
    uint8_t  payload[MAX_PAYLOAD];/* actual data (file bytes, etc.)     */
} packet;

/* ——— Helper function prototypes ———————————————————— */

/*
 * packet_serialize – convert a packet struct into a byte buffer in
 * network byte order.  Returns the total number of bytes written
 * (HEADER_SIZE + payload_len).
 */
int packet_serialize(packet *pkt, uint8_t *buf);

/*
 * packet_deserialize – convert a received byte buffer back into a
 * packet struct (host byte order).  'len' is the number of bytes read
 * from recvfrom().  Returns 0 on success, -1 on error.
 */
int packet_deserialize(uint8_t *buf, int len, packet *pkt);

/*
 * make_packet – convenience builder; fills *pkt with the supplied
 * fields and copies data into the payload if data != NULL.  Returns
 * a filled-in packet struct.
 */
packet make_packet(uint32_t seq, uint32_t ack, uint32_t flags,
                   uint8_t *data, uint32_t data_len);

/*
 * log_packet – write a single log line for a sent or received packet.
 * direction should be "SEND" or "RECV".  Flushes the file so logs
 * appear immediately.
 */
void log_packet(FILE *logfp, const char *direction, packet *pkt);

/*
 * timestamp – fill buf with "YYYY-MM-DD-HH-MM-SS".
 */
void timestamp(char *buf, size_t len);

#endif /* PROTOCOL_H */
