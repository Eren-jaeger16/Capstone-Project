/*
Below is a detailed, step-by-step design and guidance on implementing a lightweight custom protocol on top of your existing TLS (PSK-based) 
secure channel to exchange certificates. The approach assumes that you have already established a secure TLS tunnel using mbedtls with a PSK, 
and now you want to send certificates (files) from one peer to the other. We will design a simple, message-based protocol, and then outline how 
to implement it.

High-Level Goals

Use the existing secure channel: You already have a TLS connection established using PSK. 
Your data is therefore encrypted and authenticated, which greatly simplifies the protocol 
design—no need to handle cryptographic concerns at this stage. Lightweight and simple: Keep
the protocol small and straightforward. Use a simple framing format with a header that indicates:
The type of message (e.g., request, response, certificate data, etc.)
The length of the payload
The payload (the actual certificate data)
One-way or two-way exchange: Decide whether the client requests a certificate from the server,
the server pushes a certificate to the client, or both ways. The design below assumes you want a 
symmetric capability (both can send/receive). Extensibility: If in the future you want to send 
different file types or multiple certificates, you can extend the protocol by defining additional 
message types or adding a simple negotiation phase. Protocol Message Format:

Define a simple message structure. For instance:

   +----------+----------+-------------------+
   | Msg Type | Length   | Payload           |
   | (1 byte) | (4 bytes)| (variable length) |
   +----------+----------+-------------------+
Msg Type: A single byte that indicates the message type. For example:
0x01: REQUEST_CERT (Client asks the server to send its certificate)
0x02: CERT_INFO (Response from the server with certificate metadata)
0x03: CERT_DATA (Certificate chunk payload)
0x04: TRANSFER_COMPLETE (Indicates that the file/certificate transfer is done)
Length: A 4-byte (uint32_t) length field in network byte order (big-endian) indicating how many bytes of payload follow.
Payload: Variable-length data dependent on the message type.
For REQUEST_CERT, the payload could be empty or could contain an identifier string if multiple certificates are available.
For CERT_INFO, the payload might include the total size of the certificate and possibly a filename or type (PEM, DER).
For CERT_DATA, the payload is a raw chunk of the certificate file.
For TRANSFER_COMPLETE, the payload can be empty or contain a status code.
This simple structure makes it easy to parse and is extensible if you want to add other message types later.
*/

int send_message(mbedtls_ssl_context *ssl, uint8_t msg_type, const uint8_t *payload, uint32_t payload_len) {
    uint8_t header[5]; // 1 byte type + 4 bytes length
    header[0] = msg_type;
    uint32_t net_len = htonl(payload_len);
    memcpy(header + 1, &net_len, 4);

    // Write header
    int ret = mbedtls_ssl_write(ssl, header, 5);
    if (ret < 0) return ret;

    // Write payload if any
    if (payload_len > 0) {
        ret = mbedtls_ssl_write(ssl, payload, payload_len);
        if (ret < 0) return ret;
    }
    return 0;
}

/*Basic Exchange Flow

Assume the following scenario: The client wants to get the server’s certificate.

Client Sends REQUEST_CERT:
Type = 0x01 (REQUEST_CERT)
Length = 0 (no payload needed if not distinguishing multiple certs)
The client writes this message to the TLS channel.
Server Responds with CERT_INFO:
Type = 0x02 (CERT_INFO)
Payload:
First 4 bytes: total certificate size in bytes (uint32_t)
Next N bytes: optional filename or description (not strictly required)
The server obtains its certificate file from disk, gets its size, and sends this info to the client.
Server Sends CERT_DATA in Chunks:
The server reads the certificate file in fixed-size chunks (e.g., 4 KB).
For each chunk:
Type = 0x03 (CERT_DATA)
Length = size_of_this_chunk (e.g., 4096 bytes)
Payload: actual 4096 bytes of certificate data.
The server sends multiple CERT_DATA messages until the entire certificate is sent.
Server Sends TRANSFER_COMPLETE:
Type = 0x04 (TRANSFER_COMPLETE)
Length = 0
Payload: none
This tells the client the entire certificate is transmitted.
Client Receives and Reconstructs:
The client receives CERT_INFO, notes the total length.
The client receives successive CERT_DATA chunks, writing them into a local file buffer.
Once TRANSFER_COMPLETE is received, the client knows the file is fully transferred and can close the file handle or proceed with validation.
For sending from client to server, just reverse the roles. The exact same message types and logic can apply.

Implementation Steps in C using mbedtls

Prerequisites: You have a working TLS connection (via mbedtls_ssl_write() and mbedtls_ssl_read()).

1. Writing a Function to Send a Message
*/

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h> // For htonl()

int send_message(mbedtls_ssl_context *ssl, uint8_t msg_type, const uint8_t *payload, uint32_t payload_len) {
    uint8_t header[5]; // 1 byte type + 4 bytes length
    header[0] = msg_type;
    uint32_t net_len = htonl(payload_len);
    memcpy(header + 1, &net_len, 4);

    // Write header
    int ret = mbedtls_ssl_write(ssl, header, 5);
    if (ret < 0) return ret;

    // Write payload if any
    if (payload_len > 0) {
        ret = mbedtls_ssl_write(ssl, payload, payload_len);
        if (ret < 0) return ret;
    }
    return 0;
}

//This function writes a single protocol message. It sends the message type and length, then sends the payload in a separate call. You could also combine them if desired.

//2. Reading a Message
//Create a function to read a complete message from the TLS connection. This function first reads the 5-byte header, then allocates or uses a buffer to read the payload.

int read_message(mbedtls_ssl_context *ssl, uint8_t *msg_type, uint8_t *buf, uint32_t buf_size, uint32_t *payload_len_out) {
    uint8_t header[5];
    int ret = mbedtls_ssl_read(ssl, header, 5);
    if (ret <= 0) return ret; // handle errors or interruptions

    *msg_type = header[0];
    uint32_t net_len;
    memcpy(&net_len, header + 1, 4);
    uint32_t payload_len = ntohl(net_len);

    if (payload_len > buf_size) {
        // Payload too large for buffer - handle error
        return -1;
    }

    ret = mbedtls_ssl_read(ssl, buf, payload_len);
    if (ret <= 0) return ret; // handle errors

    *payload_len_out = payload_len;
    return 0;
}
//This function reads a single message into a provided buffer. In a real implementation, you might dynamically allocate the buffer or handle partial reads carefully.

//3. Requesting a Certificate (Client Side)
int request_certificate(mbedtls_ssl_context *ssl) {
    // Send a REQUEST_CERT message (type 0x01)
    int ret = send_message(ssl, 0x01, NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "Failed to send REQUEST_CERT: %d\n", ret);
        return ret;
    }

    // Read response (CERT_INFO)
    uint8_t msg_type;
    uint8_t buffer[1024]; // buffer large enough to hold info
    uint32_t payload_len;
    ret = read_message(ssl, &msg_type, buffer, sizeof(buffer), &payload_len);
    if (ret < 0) {
        fprintf(stderr, "Failed to read CERT_INFO: %d\n", ret);
        return ret;
    }

    if (msg_type != 0x02) {
        fprintf(stderr, "Unexpected message type %d\n", msg_type);
        return -1;
    }

    // Extract total certificate size from CERT_INFO payload
    if (payload_len < 4) {
        fprintf(stderr, "CERT_INFO payload too small\n");
        return -1;
    }

    uint32_t total_cert_size;
    memcpy(&total_cert_size, buffer, 4);
    total_cert_size = ntohl(total_cert_size);

    // Optional: read filename if present
    // char filename[...]; // parse as needed

    // Now read CERT_DATA messages until we get the whole certificate
    FILE *f = fopen("received_cert.der", "wb");
    if (!f) {
        perror("fopen");
        return -1;
    }

    uint32_t bytes_received = 0;
    while (bytes_received < total_cert_size) {
        ret = read_message(ssl, &msg_type, buffer, sizeof(buffer), &payload_len);
        if (ret < 0) {
            fprintf(stderr, "Failed to read CERT_DATA: %d\n", ret);
            fclose(f);
            return ret;
        }

        if (msg_type == 0x03) { // CERT_DATA
            fwrite(buffer, 1, payload_len, f);
            bytes_received += payload_len;
        } else if (msg_type == 0x04) { // TRANSFER_COMPLETE
            // Verify we received the expected amount
            if (bytes_received == total_cert_size) {
                printf("Certificate transfer complete.\n");
            } else {
                fprintf(stderr, "TRANSFER_COMPLETE received but not all data read.\n");
            }
            break;
        } else {
            fprintf(stderr, "Unexpected message type %d during data reception.\n", msg_type);
            fclose(f);
            return -1;
        }
    }

    fclose(f);
    return 0;
}

//This function requests the certificate from the server and writes it to a local file. The same logic can be reversed to allow the server to request from the client.

//4. Serving the Certificate (Server Side)

int serve_certificate(mbedtls_ssl_context *ssl, const char *cert_path) {
    // Wait for REQUEST_CERT
    uint8_t msg_type;
    uint8_t buffer[1024];
    uint32_t payload_len;
    int ret = read_message(ssl, &msg_type, buffer, sizeof(buffer), &payload_len);
    if (ret < 0) {
        fprintf(stderr, "Failed to read request: %d\n", ret);
        return ret;
    }

    if (msg_type != 0x01) {
        fprintf(stderr, "Expected REQUEST_CERT, got %d\n", msg_type);
        return -1;
    }

    // Open certificate file
    FILE *f = fopen(cert_path, "rb");
    if (!f) {
        perror("fopen");
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long cert_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    // Send CERT_INFO
    // Payload: [4 bytes: total size][Optional: filename/metadata]
    uint8_t info_payload[4];
    uint32_t net_size = htonl((uint32_t)cert_size);
    memcpy(info_payload, &net_size, 4);
    ret = send_message(ssl, 0x02, info_payload, 4);
    if (ret < 0) {
        fclose(f);
        fprintf(stderr, "Failed to send CERT_INFO: %d\n", ret);
        return ret;
    }

    // Send CERT_DATA in chunks
    uint8_t data_chunk[4096];
    size_t n;
    while ((n = fread(data_chunk, 1, sizeof(data_chunk), f)) > 0) {
        ret = send_message(ssl, 0x03, data_chunk, (uint32_t)n);
        if (ret < 0) {
            fclose(f);
            fprintf(stderr, "Failed to send CERT_DATA chunk: %d\n", ret);
            return ret;
        }
    }

    fclose(f);

    // Send TRANSFER_COMPLETE
    ret = send_message(ssl, 0x04, NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "Failed to send TRANSFER_COMPLETE: %d\n", ret);
        return ret;
    }

    return 0;
}

/*This server-side function waits for a REQUEST_CERT and then sends the file in CERT_INFO and CERT_DATA messages, finishing with TRANSFER_COMPLETE.

5. Error Handling and Edge Cases
Partial Reads/Writes: mbedtls_ssl_read() and mbedtls_ssl_write() might not read/write the entire requested amount in one call. You might need loops to ensure you read/write the full amount. The sample code above assumes you get the full amount. In production, wrap these calls in helper functions that ensure full reads/writes.
Timeouts and Interruptions: Handle SSL interruptions (e.g., MBEDTLS_ERR_SSL_WANT_READ/_WRITE) by re-calling the functions as needed.
Versioning: Consider adding a protocol version byte at the start of your exchange if you plan long-term maintenance.
Multiple Certificates: If you need to handle multiple certificates, include an identifier in the REQUEST_CERT payload and parse it in the server, or allow the server to send a list first.
6. Testing
Test with a small certificate file first.
Enable debug logs in mbedtls to see if messages are going through correctly.
Check that the received file matches the sent file byte-for-byte.
Add print statements when reading/writing messages to ensure correct message types and sizes.
Summary

By following the above steps, you will have:

A simple binary protocol layered on top of TLS/PSK.
Defined message types and structures for exchanging certificate files.
Basic sender and receiver functions for both client and server.
A foundation that is easy to extend for other file types or metadata if needed.