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



/* To make the protocol non-blocking and implemented as a state machine, we'll modify it so the server and
    client can handle other tasks while waiting for messages or writing them. A state machine allows us to
manage the connection’s behavior systematically. Here’s a step-by-step implementation:*/

/*Key Modifications
Non-Blocking I/O:
Use non-blocking sockets with mbedtls_net_set_nonblock for asynchronous reads/writes.
Poll sockets regularly to check for data availability.
State Machine:
Each party (client/server) uses states to track the protocol's progress.
Transition between states based on the events (e.g., data received, data sent).
Error Handling:
Handle errors like MBEDTLS_ERR_SSL_WANT_READ and MBEDTLS_ERR_SSL_WANT_WRITE gracefully to retry later.
Protocol States
Server States

WAIT_FOR_CERT_REQ: Waiting for the client’s CERT_REQ message.
SEND_CERT_RESP: Sending the CERT_RESP message with the certificate.
WAIT_FOR_ACK: Waiting for the client’s acknowledgment (ACK).
DONE: Protocol completed.
Client States

SEND_CERT_REQ: Sending the CERT_REQ message.
WAIT_FOR_CERT_RESP: Waiting for the server’s CERT_RESP message.
SEND_ACK: Sending the acknowledgment (ACK).
DONE: Protocol completed.
Server Implementation (Non-Blocking + State Machine)
Server State Machine*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#define CERT_REQ  0x01
#define CERT_RESP 0x02
#define ACK       0x03

typedef enum {
    WAIT_FOR_CERT_REQ,
    SEND_CERT_RESP,
    WAIT_FOR_ACK,
    DONE
} ServerState;

typedef struct {
    ServerState state;
    mbedtls_ssl_context *ssl;
    const char *cert_path;
    size_t bytes_sent;
    size_t total_bytes_to_send;
    uint8_t buffer[1024];
} ServerProtocol;

void server_run_nonblocking(ServerProtocol *protocol) {
    int ret;

    while (protocol->state != DONE) {
        switch (protocol->state) {
            case WAIT_FOR_CERT_REQ: {
                uint8_t header[5];
                ret = mbedtls_ssl_read(protocol->ssl, header, sizeof(header));

                if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
                    break; // Non-blocking: try again later
                } else if (ret <= 0) {
                    perror("Error reading CERT_REQ");
                    exit(EXIT_FAILURE);
                }

                if (header[0] == CERT_REQ) {
                    printf("CERT_REQ received.\n");
                    protocol->state = SEND_CERT_RESP;
                } else {
                    fprintf(stderr, "Unexpected message type: 0x%02x\n", header[0]);
                }
                break;
            }

            case SEND_CERT_RESP: {
                FILE *file = fopen(protocol->cert_path, "rb");
                if (!file) {
                    perror("Error opening certificate file");
                    exit(EXIT_FAILURE);
                }

                fseek(file, 0, SEEK_END);
                protocol->total_bytes_to_send = ftell(file);
                rewind(file);

                size_t cert_size = fread(protocol->buffer + 5, 1, sizeof(protocol->buffer) - 5, file);
                fclose(file);

                // Prepare header
                protocol->buffer[0] = CERT_RESP;
                uint32_t payload_size = htonl(cert_size);
                memcpy(&protocol->buffer[1], &payload_size, sizeof(payload_size));

                protocol->bytes_sent = 0;

                // Send data non-blocking
                ret = mbedtls_ssl_write(protocol->ssl, protocol->buffer, cert_size + 5);
                if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                    break; // Non-blocking: try again later
                } else if (ret <= 0) {
                    perror("Error sending CERT_RESP");
                    exit(EXIT_FAILURE);
                }

                protocol->state = WAIT_FOR_ACK;
                printf("CERT_RESP sent.\n");
                break;
            }

            case WAIT_FOR_ACK: {
                uint8_t ack[5];
                ret = mbedtls_ssl_read(protocol->ssl, ack, sizeof(ack));

                if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
                    break; // Non-blocking: try again later
                } else if (ret <= 0) {
                    perror("Error reading ACK");
                    exit(EXIT_FAILURE);
                }

                if (ack[0] == ACK) {
                    printf("ACK received.\n");
                    protocol->state = DONE;
                } else {
                    fprintf(stderr, "Unexpected message type: 0x%02x\n", ack[0]);
                }
                break;
            }

            case DONE:
                break;
        }
    }
}
//Client Implementation (Non-Blocking + State Machine)
//Client State Machine

typedef enum {
    SEND_CERT_REQ,
    WAIT_FOR_CERT_RESP,
    SEND_ACK,
    DONE
} ClientState;

typedef struct {
    ClientState state;
    mbedtls_ssl_context *ssl;
    size_t bytes_received;
    size_t total_bytes_to_receive;
    uint8_t buffer[1024];
} ClientProtocol;

void client_run_nonblocking(ClientProtocol *protocol) {
    int ret;

    while (protocol->state != DONE) {
        switch (protocol->state) {
            case SEND_CERT_REQ: {
                uint8_t cert_req[5] = {CERT_REQ, 0, 0, 0, 0};
                ret = mbedtls_ssl_write(protocol->ssl, cert_req, sizeof(cert_req));

                if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                    break; // Non-blocking: try again later
                } else if (ret <= 0) {
                    perror("Error sending CERT_REQ");
                    exit(EXIT_FAILURE);
                }

                protocol->state = WAIT_FOR_CERT_RESP;
                printf("CERT_REQ sent.\n");
                break;
            }

            case WAIT_FOR_CERT_RESP: {
                ret = mbedtls_ssl_read(protocol->ssl, protocol->buffer, sizeof(protocol->buffer));

                if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
                    break; // Non-blocking: try again later
                } else if (ret <= 0) {
                    perror("Error receiving CERT_RESP");
                    exit(EXIT_FAILURE);
                }

                printf("CERT_RESP received. Saving certificate.\n");
                FILE *file = fopen("received_cert.pem", "wb");
                fwrite(protocol->buffer + 5, 1, ret - 5, file);
                fclose(file);

                protocol->state = SEND_ACK;
                break;
            }

            case SEND_ACK: {
                uint8_t ack[5] = {ACK, 0, 0, 0, 0};
                ret = mbedtls_ssl_write(protocol->ssl, ack, sizeof(ack));

                if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                    break; // Non-blocking: try again later
                } else if (ret <= 0) {
                    perror("Error sending ACK");
                    exit(EXIT_FAILURE);
                }

                protocol->state = DONE;
                printf("ACK sent.\n");
                break;
            }

            case DONE:
                break;
        }
    }
}
/*Integration
Set non-blocking mode:
mbedtls_net_set_nonblock(&ssl_context);
Call server_run_nonblocking and client_run_nonblocking repeatedly in your event loop 
or timer-based system.
Testing
Start the server and let it handle multiple clients asynchronously.
Run the client and verify that the state transitions occur correctly.
This approach is efficient for embedded and multi-client environments where blocking 
calls are impractical. Let me know if you need additional details!




Please explain in more details.
And you didn't provide a such an asynchronous communication for the initial connection 
    (handshake) before the protocol is to happen
ChatGPT said:*/


/*You're absolutely right that the handshake step also needs to be non-blocking for the entire
communication process to function asynchronously. Let me explain this in more detail, step by 
step, and cover how to make the handshake asynchronous alongside the protocol.

Asynchronous Communication in TLS
When using TLS with mbedtls, operations like ssl_handshake, ssl_read, and ssl_write are 
typically blocking. To make them asynchronous:

Use non-blocking sockets: This allows the program to poll the socket or wait for data/events 
without halting execution.
Handle MBEDTLS_ERR_SSL_WANT_READ and MBEDTLS_ERR_SSL_WANT_WRITE errors: These indicate that the 
TLS operation couldn't complete yet because the socket wasn't ready.
Non-Blocking Handshake
Before starting the custom protocol, the TLS handshake must be completed. Here's how to implement
a non-blocking handshake using a state machine.

Handshake States

Define states to track handshake progress:

HANDSHAKE_INIT: Start the handshake.
HANDSHAKE_PROCESS: Process the handshake in small steps.
HANDSHAKE_DONE: Handshake is complete.
Server-Side Handshake*/

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

typedef enum {
    HANDSHAKE_INIT,
    HANDSHAKE_PROCESS,
    HANDSHAKE_DONE
} HandshakeState;

typedef struct {
    HandshakeState state;
    mbedtls_ssl_context *ssl;
} HandshakeProtocol;

void server_handshake_nonblocking(HandshakeProtocol *protocol) {
    int ret;

    while (protocol->state != HANDSHAKE_DONE) {
        switch (protocol->state) {
            case HANDSHAKE_INIT:
                protocol->state = HANDSHAKE_PROCESS;
                break;

            case HANDSHAKE_PROCESS:
                ret = mbedtls_ssl_handshake(protocol->ssl);

                if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                    break; // Non-blocking: retry handshake later
                } else if (ret != 0) {
                    printf("TLS handshake failed with error: %d\n", ret);
                    exit(EXIT_FAILURE);
                }

                printf("TLS handshake completed.\n");
                protocol->state = HANDSHAKE_DONE;
                break;

            case HANDSHAKE_DONE:
                break;
        }
    }
}
/*Client-Side Handshake

The client handshake process is similar, with the same state transitions.

Integrating Non-Blocking Handshake with the Custom Protocol
Once the handshake is complete, the state machine can transition to the 
custom protocol’s states. Below, I’ll explain how the protocol works asynchronously
after the handshake.

Server State Machine with Handshake and Protocol
Complete State Diagram

Here’s how the server transitions through states:

Handshake States:
HANDSHAKE_INIT
HANDSHAKE_PROCESS
HANDSHAKE_DONE
Protocol States:
WAIT_FOR_CERT_REQ
SEND_CERT_RESP
WAIT_FOR_ACK
DONE
Implementation*/

typedef enum {
    HANDSHAKE_INIT,
    HANDSHAKE_PROCESS,
    HANDSHAKE_DONE,
    WAIT_FOR_CERT_REQ,
    SEND_CERT_RESP,
    WAIT_FOR_ACK,
    DONE
} ServerState;

typedef struct {
    ServerState state;
    mbedtls_ssl_context *ssl;
    const char *cert_path;
    size_t bytes_sent;
    size_t total_bytes_to_send;
    uint8_t buffer[1024];
} ServerProtocol;

void server_run_nonblocking(ServerProtocol *protocol) {
    int ret;

    while (protocol->state != DONE) {
        switch (protocol->state) {
            case HANDSHAKE_INIT:
                protocol->state = HANDSHAKE_PROCESS;
                break;

            case HANDSHAKE_PROCESS:
                ret = mbedtls_ssl_handshake(protocol->ssl);
                if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                    break; // Non-blocking: retry later
                } else if (ret != 0) {
                    printf("Handshake failed: %d\n", ret);
                    exit(EXIT_FAILURE);
                }
                printf("TLS handshake complete.\n");
                protocol->state = WAIT_FOR_CERT_REQ;
                break;

            case WAIT_FOR_CERT_REQ: {
                uint8_t header[5];
                ret = mbedtls_ssl_read(protocol->ssl, header, sizeof(header));
                if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
                    break; // Non-blocking: retry later
                } else if (ret <= 0) {
                    printf("Error reading CERT_REQ.\n");
                    exit(EXIT_FAILURE);
                }
                if (header[0] == CERT_REQ) {
                    printf("CERT_REQ received.\n");
                    protocol->state = SEND_CERT_RESP;
                }
                break;
            }

            case SEND_CERT_RESP: {
                FILE *file = fopen(protocol->cert_path, "rb");
                if (!file) {
                    perror("Error opening certificate file");
                    exit(EXIT_FAILURE);
                }
                fseek(file, 0, SEEK_END);
                protocol->total_bytes_to_send = ftell(file);
                rewind(file);

                size_t cert_size = fread(protocol->buffer + 5, 1, sizeof(protocol->buffer) - 5, file);
                fclose(file);

                // Prepare CERT_RESP header
                protocol->buffer[0] = CERT_RESP;
                uint32_t payload_size = htonl(cert_size);
                memcpy(&protocol->buffer[1], &payload_size, sizeof(payload_size));

                protocol->bytes_sent = 0;
                ret = mbedtls_ssl_write(protocol->ssl, protocol->buffer, cert_size + 5);
                if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                    break; // Non-blocking: retry later
                } else if (ret <= 0) {
                    printf("Error sending CERT_RESP.\n");
                    exit(EXIT_FAILURE);
                }

                protocol->state = WAIT_FOR_ACK;
                printf("CERT_RESP sent.\n");
                break;
            }

            case WAIT_FOR_ACK: {
                uint8_t ack[5];
                ret = mbedtls_ssl_read(protocol->ssl, ack, sizeof(ack));
                if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
                    break; // Non-blocking: retry later
                } else if (ret <= 0) {
                    printf("Error reading ACK.\n");
                    exit(EXIT_FAILURE);
                }
                if (ack[0] == ACK) {
                    printf("ACK received.\n");
                    protocol->state = DONE;
                }
                break;
            }

            case DONE:
                break;
        }
    }
}
/*Client State Machine
The client state machine follows a similar structure:

HANDSHAKE_INIT → HANDSHAKE_PROCESS → HANDSHAKE_DONE
SEND_CERT_REQ → WAIT_FOR_CERT_RESP → SEND_ACK → DONE
Key Points
Handshake Non-Blocking: Both the client and server handle ssl_handshake in a non-blocking 
way using MBEDTLS_ERR_SSL_WANT_READ/WRITE.
Custom Protocol Non-Blocking: Handle ssl_read and ssl_write similarly for the protocol steps.
State Machine: The entire process, from handshake to protocol, is divided into states that 
transition based on socket readiness.
Would you like me to provide the complete client-side implementation or further explanations?*/


/*Provide the complete client side implementation please
ChatGPT said:

ChatGPT
Here’s the complete non-blocking client-side implementation using a state machine. This includes
the handshake and the custom protocol for certificate exchange.

Client State Machine
The client will transition through the following states:

Handshake States:
HANDSHAKE_INIT: Start the handshake.
HANDSHAKE_PROCESS: Process the handshake in small steps.
HANDSHAKE_DONE: Handshake is complete.
Protocol States:
SEND_CERT_REQ: Send the CERT_REQ message to the server.
WAIT_FOR_CERT_RESP: Wait for the server's CERT_RESP message.
SEND_ACK: Send the acknowledgment (ACK) to the server.
DONE: Protocol is complete.
Complete Code*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#define CERT_REQ  0x01
#define CERT_RESP 0x02
#define ACK       0x03

typedef enum {
    HANDSHAKE_INIT,
    HANDSHAKE_PROCESS,
    HANDSHAKE_DONE,
    SEND_CERT_REQ,
    WAIT_FOR_CERT_RESP,
    SEND_ACK,
    DONE
} ClientState;

typedef struct {
    ClientState state;
    mbedtls_ssl_context *ssl;
    uint8_t buffer[1024];
    size_t bytes_received;
} ClientProtocol;

void client_run_nonblocking(ClientProtocol *protocol) {
    int ret;

    while (protocol->state != DONE) {
        switch (protocol->state) {
            case HANDSHAKE_INIT:
                protocol->state = HANDSHAKE_PROCESS;
                break;

            case HANDSHAKE_PROCESS:
                ret = mbedtls_ssl_handshake(protocol->ssl);
                if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                    break; // Non-blocking: try again later
                } else if (ret != 0) {
                    printf("TLS handshake failed: -0x%04x\n", -ret);
                    exit(EXIT_FAILURE);
                }
                printf("TLS handshake completed.\n");
                protocol->state = SEND_CERT_REQ;
                break;

            case SEND_CERT_REQ: {
                uint8_t cert_req[5] = {CERT_REQ, 0, 0, 0, 0}; // CERT_REQ message with no payload
                ret = mbedtls_ssl_write(protocol->ssl, cert_req, sizeof(cert_req));
                if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                    break; // Non-blocking: try again later
                } else if (ret <= 0) {
                    printf("Error sending CERT_REQ: -0x%04x\n", -ret);
                    exit(EXIT_FAILURE);
                }
                printf("CERT_REQ sent.\n");
                protocol->state = WAIT_FOR_CERT_RESP;
                break;
            }

            case WAIT_FOR_CERT_RESP: {
                ret = mbedtls_ssl_read(protocol->ssl, protocol->buffer, sizeof(protocol->buffer));
                if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
                    break; // Non-blocking: try again later
                } else if (ret <= 0) {
                    printf("Error receiving CERT_RESP: -0x%04x\n", -ret);
                    exit(EXIT_FAILURE);
                }

                // Process CERT_RESP
                if (protocol->buffer[0] != CERT_RESP) {
                    printf("Unexpected message type: 0x%02x\n", protocol->buffer[0]);
                    exit(EXIT_FAILURE);
                }

                uint32_t payload_size;
                memcpy(&payload_size, &protocol->buffer[1], sizeof(payload_size));
                payload_size = ntohl(payload_size);

                printf("CERT_RESP received. Payload size: %u bytes.\n", payload_size);

                // Save the certificate
                FILE *file = fopen("received_cert.pem", "wb");
                if (!file) {
                    perror("Error opening file to save certificate");
                    exit(EXIT_FAILURE);
                }
                fwrite(protocol->buffer + 5, 1, ret - 5, file);
                fclose(file);

                printf("Certificate saved to 'received_cert.pem'.\n");
                protocol->state = SEND_ACK;
                break;
            }

            case SEND_ACK: {
                uint8_t ack[5] = {ACK, 0, 0, 0, 0}; // ACK message with no payload
                ret = mbedtls_ssl_write(protocol->ssl, ack, sizeof(ack));
                if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                    break; // Non-blocking: try again later
                } else if (ret <= 0) {
                    printf("Error sending ACK: -0x%04x\n", -ret);
                    exit(EXIT_FAILURE);
                }
                printf("ACK sent.\n");
                protocol->state = DONE;
                break;
            }

            case DONE:
                printf("Client protocol completed successfully.\n");
                break;
        }
    }
}
/*Setup and Integration
Initialization

Before calling client_run_nonblocking, initialize the ClientProtocol structure
and set up the TLS connection:*/

void initialize_client_protocol(ClientProtocol *protocol, mbedtls_ssl_context *ssl) {
    protocol->state = HANDSHAKE_INIT;
    protocol->ssl = ssl;
    memset(protocol->buffer, 0, sizeof(protocol->buffer));
    protocol->bytes_received = 0;
}
//Non-Blocking TLS Setup

//Set the TLS connection to non-blocking mode using:

mbedtls_net_set_nonblock(&ssl_context);
//This ensures that mbedtls_ssl_handshake, mbedtls_ssl_read, and mbedtls_ssl_write return immediately when the socket is not ready.

/*How the Non-Blocking State Machine Works
Handshake:
The handshake is performed incrementally in the HANDSHAKE_PROCESS state.
If the handshake function returns MBEDTLS_ERR_SSL_WANT_READ or MBEDTLS_ERR_SSL_WANT_WRITE, the program retries later.
Protocol:
Each step of the protocol (e.g., sending CERT_REQ, waiting for CERT_RESP) is handled in its respective state.
Transitions occur based on events like successful reads or writes.
Non-Blocking Logic:
Reads and writes check for MBEDTLS_ERR_SSL_WANT_READ or MBEDTLS_ERR_SSL_WANT_WRITE and retry later without blocking execution.
Testing the Client
Start the server with its state machine running.
Run the client and observe the state transitions.
Ensure that:
The handshake completes.
The CERT_REQ is sent.
The CERT_RESP is received and saved as received_cert.pem.
The ACK is sent.
Advantages of the Non-Blocking State Machine
Efficiency: The client doesn’t block while waiting for server responses.
Scalability: Multiple clients can operate concurrently in event-driven environments.
Flexibility: The state machine can be extended for additional protocol steps.*/
