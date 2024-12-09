/*Message Types

CERT_REQ (0x01): Client requests the certificate.
CERT_RESP (0x02): Server sends the certificate.
ACK (0x03): Client acknowledges receipt of the certificate.
Message Format

| Type (1 byte) | Payload Size (4 bytes) | Payload (variable) |
Type: Indicates the type of the message.
Payload Size: A 4-byte integer (network byte order) indicating the size of the payload.
Payload: The actual certificate data (optional for certain types).
2. Implementing the Server
The server will:

Wait for a CERT_REQ.
Send a CERT_RESP containing its certificate.
Wait for an ACK.
Here’s a simplified implementation:

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
*/

#define CERT_RESP 0x02
#define ACK 0x03

void send_cert_resp(mbedtls_ssl_context *ssl, const char *cert_path) {
    FILE *file = fopen(cert_path, "rb");
    if (!file) {
        perror("Error opening certificate file");
        exit(EXIT_FAILURE);
    }

    // Load certificate into memory
    fseek(file, 0, SEEK_END);
    long cert_size = ftell(file);
    rewind(file);

    uint8_t *cert_data = malloc(cert_size);
    if (fread(cert_data, 1, cert_size, file) != cert_size) {
        perror("Error reading certificate file");
        fclose(file);
        free(cert_data);
        exit(EXIT_FAILURE);
    }
    fclose(file);

    // Construct CERT_RESP message
    uint8_t header[5];
    header[0] = CERT_RESP;
    uint32_t payload_size = htonl(cert_size);
    memcpy(&header[1], &payload_size, sizeof(payload_size));

    // Send header
    if (mbedtls_ssl_write(ssl, header, sizeof(header)) <= 0) {
        perror("Error sending CERT_RESP header");
        free(cert_data);
        exit(EXIT_FAILURE);
    }

    // Send payload
    if (mbedtls_ssl_write(ssl, cert_data, cert_size) <= 0) {
        perror("Error sending CERT_RESP payload");
        free(cert_data);
        exit(EXIT_FAILURE);
    }

    free(cert_data);
    printf("Certificate sent successfully.\n");
}

void wait_for_ack(mbedtls_ssl_context *ssl) {
    uint8_t buffer[5];
    if (mbedtls_ssl_read(ssl, buffer, sizeof(buffer)) <= 0) {
        perror("Error reading ACK");
        exit(EXIT_FAILURE);
    }
    if (buffer[0] != ACK) {
        fprintf(stderr, "Unexpected message type: 0x%02x\n", buffer[0]);
        exit(EXIT_FAILURE);
    }
    printf("ACK received.\n");
}

// Main server logic (add TLS setup here)
void server_run(mbedtls_ssl_context *ssl) {
    // Wait for CERT_REQ
    uint8_t buffer[5];
    if (mbedtls_ssl_read(ssl, buffer, sizeof(buffer)) <= 0) {
        perror("Error reading CERT_REQ");
        exit(EXIT_FAILURE);
    }

    if (buffer[0] != 0x01) {
        fprintf(stderr, "Unexpected message type: 0x%02x\n", buffer[0]);
        exit(EXIT_FAILURE);
    }

    printf("CERT_REQ received.\n");

    // Send CERT_RESP
    send_cert_resp(ssl, "server_cert.pem");

    // Wait for ACK
    wait_for_ack(ssl);
}
//3. Implementing the Client
//The client will:
/*
Send a CERT_REQ.
Wait for a CERT_RESP.
Send an ACK.
Here’s a client implementation:


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
*/

#define CERT_REQ 0x01
#define CERT_RESP 0x02
#define ACK 0x03

void send_cert_req(mbedtls_ssl_context *ssl) {
    uint8_t header[5] = {CERT_REQ, 0, 0, 0, 0}; // CERT_REQ with no payload
    if (mbedtls_ssl_write(ssl, header, sizeof(header)) <= 0) {
        perror("Error sending CERT_REQ");
        exit(EXIT_FAILURE);
    }
    printf("CERT_REQ sent.\n");
}

void receive_cert_resp(mbedtls_ssl_context *ssl, const char *save_path) {
    uint8_t header[5];
    if (mbedtls_ssl_read(ssl, header, sizeof(header)) <= 0) {
        perror("Error reading CERT_RESP header");
        exit(EXIT_FAILURE);
    }

    if (header[0] != CERT_RESP) {
        fprintf(stderr, "Unexpected message type: 0x%02x\n", header[0]);
        exit(EXIT_FAILURE);
    }

    uint32_t payload_size;
    memcpy(&payload_size, &header[1], sizeof(payload_size));
    payload_size = ntohl(payload_size);

    uint8_t *cert_data = malloc(payload_size);
    if (mbedtls_ssl_read(ssl, cert_data, payload_size) <= 0) {
        perror("Error reading CERT_RESP payload");
        free(cert_data);
        exit(EXIT_FAILURE);
    }

    FILE *file = fopen(save_path, "wb");
    if (!file) {
        perror("Error opening file to save certificate");
        free(cert_data);
        exit(EXIT_FAILURE);
    }

    fwrite(cert_data, 1, payload_size, file);
    fclose(file);
    free(cert_data);

    printf("Certificate received and saved to %s.\n", save_path);
}

void send_ack(mbedtls_ssl_context *ssl) {
    uint8_t header[5] = {ACK, 0, 0, 0, 0}; // ACK with no payload
    if (mbedtls_ssl_write(ssl, header, sizeof(header)) <= 0) {
        perror("Error sending ACK");
        exit(EXIT_FAILURE);
    }
    printf("ACK sent.\n");
}

// Main client logic (add TLS setup here)
void client_run(mbedtls_ssl_context *ssl) {
    // Send CERT_REQ
    send_cert_req(ssl);

    // Receive CERT_RESP
    receive_cert_resp(ssl, "server_cert_received.pem");

    // Send ACK
    send_ack(ssl);
}
/*4. Integration with Your TLS Setup
Integrate the server_run and client_run functions with your existing TLS client and server setup.
Use mbedtls_ssl_setup and mbedtls_ssl_handshake as you already do, then call the custom protocol logic.
5. Testing
Start the server and ensure it listens for incoming connections.
Run the client to initiate the protocol.
Verify that the certificate is successfully transferred and saved.
Would you like help with integrating this protocol into your existing TLS setup?*/