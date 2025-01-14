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

Great! Let's walk through unit testing with the Seatest framework step by step.

What Is Unit Testing?
Unit testing verifies individual components (functions, classes, modules) of your code to ensure they behave as expected. With the Seatest framework, you'll write test cases for specific functions in your program.

Step-by-Step Guide
1. Install Seatest

If you haven’t already, download the Seatest framework. Seatest is a single header file (seatest.h), so you only need to include it in your project.

Download seatest.h from the official repository: Seatest GitHub
Place seatest.h in your project's include directory.
2. Set Up a Test Project

Create a new source file for your unit tests, e.g., test_protocol.c.
Include the following headers:
seatest.h
Your program's headers (to test your functions).
3. Write a Test Function

Each test function should focus on a single aspect of the function you're testing. Here's an example for a hypothetical send_cert_req() function.

Test Code Example: test_send_cert_req
#include "seatest.h"
#include "protocol.h" // Replace with your actual header file

// Mock TLS context (for unit testing purposes)
mbedtls_ssl_context mock_ssl;

// Test if `send_cert_req` correctly writes the CERT_REQ message
void test_send_cert_req()
{
    uint8_t buffer[5];
    int ret;

    // Mock the SSL write operation
    mbedtls_ssl_set_bio(&mock_ssl, buffer, sizeof(buffer));

    // Call the function
    ret = send_cert_req(&mock_ssl);

    // Verify the return value is success
    assert_int_equal(0, ret);

    // Verify the written data
    assert_int_equal(CERT_REQ, buffer[0]); // Type
    assert_int_equal(0, buffer[1]);        // Payload size (zero for CERT_REQ)
    assert_int_equal(0, buffer[2]);
    assert_int_equal(0, buffer[3]);
    assert_int_equal(0, buffer[4]);
}
4. Write a Suite of Tests

Group related tests into a suite. For example:

Test Suite: protocol_tests
void protocol_tests()
{
    test_fixture_start(); // Start a group of related tests
    run_test(test_send_cert_req); // Add your tests here
    // Add other related test functions
    test_fixture_end(); // End the group of tests
}
5. Set Up Main Function

Seatest requires a main() function to initialize and run your test suites:

#include "seatest.h"

// Main function to run all test suites
void all_tests()
{
    protocol_tests(); // Add other test suites here
}

int main(int argc, char **argv)
{
    return seatest_testrunner(argc, argv, all_tests);
}
6. Compile and Run

Compile the test code with your program:
gcc -o test_protocol test_protocol.c protocol.c -I. -lmbedtls
Run the tests:
./test_protocol
You’ll see output like:
Running test: test_send_cert_req
OK
Example Test Cases for Protocol Functions
1. Test send_cert_resp()

void test_send_cert_resp()
{
    uint8_t buffer[1024];
    int ret;

    // Mock the SSL context and buffer
    mbedtls_ssl_set_bio(&mock_ssl, buffer, sizeof(buffer));

    // Prepare a dummy certificate
    const char *dummy_cert = "TEST_CERTIFICATE";
    size_t cert_len = strlen(dummy_cert);

    // Call the function
    ret = send_cert_resp(&mock_ssl, dummy_cert, cert_len);

    // Verify return value
    assert_int_equal(0, ret);

    // Verify the header
    assert_int_equal(CERT_RESP, buffer[0]);
    uint32_t payload_size = (buffer[1] << 24) | (buffer[2] << 16) | (buffer[3] << 8) | buffer[4];
    assert_int_equal(cert_len, payload_size);

    // Verify the payload
    assert_string_equal(dummy_cert, (char *)&buffer[5]);
}
2. Test receive_ack()

void test_receive_ack()
{
    uint8_t buffer[5] = {ACK, 0, 0, 0, 0}; // Mock an ACK message
    int ret;

    // Mock the SSL read operation
    mbedtls_ssl_set_bio(&mock_ssl, buffer, sizeof(buffer));

    // Call the function
    ret = receive_ack(&mock_ssl);

    // Verify return value
    assert_int_equal(0, ret);
}
7. Expand Your Tests
Write similar tests for:

Timeouts: Mock delayed responses to verify timeout handling.
Retries: Simulate failures and ensure the retry logic works.
Edge Cases:
Empty buffers.
Large payloads.
Corrupted messages.
8. Debugging Failing Tests
If a test fails, Seatest will report which assertion failed, e.g.:
Running test: test_send_cert_req
Assertion failed: expected 0 but got 1 (line 24)
FAIL
Fix the implementation or refine the test case to handle the edge case appropriately.
9. Automating Tests
Automate running tests with a simple script:

#!/bin/bash
gcc -o test_protocol test_protocol.c protocol.c -I. -lmbedtls
if ./test_protocol; then
    echo "All tests passed!"
else
    echo "Some tests failed. Check the logs."
fi
Key Concepts Recap
Seatest Basics:
Use assert_* macros to verify expected behavior.
Group tests into suites and call them in main().
Mocking:
Mock dependencies (e.g., mbedtls_ssl_context) to isolate the function being tested.
Iterative Testing:
Start with small, simple test cases.
Gradually add tests for edge cases and failure scenarios.
Would you like help writing tests for specific protocol functions or automating the process further?






You said:
Help me automate everything please with explanations
ChatGPT said:

ChatGPT
Automating your unit testing workflow ensures consistency and efficiency in verifying your code's functionality. Here's how to set up a fully automated workflow, step by step.

Automation Overview
The goal is to:

Compile your program and unit tests.
Run the tests.
Report the results (success/failure) with details.
Clean up intermediate files (optional).
1. Directory Structure
Organize your project for clarity:

/project
├── /src               # Your source code
│   ├── protocol.c
│   ├── protocol.h
├── /tests             # Your test files
│   ├── test_protocol.c
│   ├── seatest.h      # Seatest framework header
├── Makefile           # Build automation
└── run_tests.sh       # Test automation script
2. Automating Compilation (Makefile)
A Makefile simplifies building your program and tests. Create a Makefile in your project root:

Makefile

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -I./src -I./tests
LDFLAGS = -lmbedtls

# Directories
SRC_DIR = src
TEST_DIR = tests
BUILD_DIR = build

# Targets
TARGET = $(BUILD_DIR)/protocol
TEST_TARGET = $(BUILD_DIR)/test_protocol

# Source files
SRC_FILES = $(SRC_DIR)/protocol.c
TEST_FILES = $(TEST_DIR)/test_protocol.c

# Build the program
$(TARGET): $(SRC_FILES)
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Build and link the tests
$(TEST_TARGET): $(SRC_FILES) $(TEST_FILES)
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Run tests
test: $(TEST_TARGET)
	./$(TEST_TARGET)

# Clean up
clean:
	rm -rf $(BUILD_DIR)
Explanation

Variables:
CC: Compiler (gcc).
CFLAGS: Compilation flags (-Wall, -Wextra for warnings, -I for include directories).
LDFLAGS: Linker flags (e.g., -lmbedtls for the mbedtls library).
Targets:
$(TARGET): Builds the main program.
$(TEST_TARGET): Builds the test program by linking your code and the test cases.
test: Compiles and runs the tests.
clean: Deletes all compiled files and intermediate artifacts.
Directories:
BUILD_DIR: A directory to store compiled binaries (avoids clutter in the project root).
3. Automating Test Execution (Shell Script)
Create a script run_tests.sh to:

Compile your program and tests.
Run the tests.
Report the results.
run_tests.sh

#!/bin/bash

# Set paths
MAKEFILE=Makefile
LOG_FILE=test_results.log

# Clear the log file
> $LOG_FILE

# Step 1: Compile the tests
echo "Compiling tests..."
make -f $MAKEFILE test >> $LOG_FILE 2>&1
if [ $? -ne 0 ]; then
    echo "Compilation failed. Check $LOG_FILE for details."
    exit 1
fi
echo "Compilation successful."

# Step 2: Run the tests
echo "Running tests..."
./build/test_protocol >> $LOG_FILE 2>&1
TEST_EXIT_CODE=$?

# Step 3: Check results
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "All tests passed successfully!"
    echo "See $LOG_FILE for details."
else
    echo "Some tests failed. Check $LOG_FILE for details."
fi

# Optional: Clean up build artifacts
echo "Cleaning up..."
make -f $MAKEFILE clean >> $LOG_FILE 2>&1
Explanation

Compiling Tests:
Runs make test to compile the tests using the Makefile.
Logs all output (stdout and stderr) to test_results.log.
Running Tests:
Executes the compiled test binary (build/test_protocol).
Captures the test binary's exit code:
0: All tests passed.
Non-zero: At least one test failed.
Cleaning Up:
Runs make clean to remove build artifacts.
4. Running the Workflow
Make the script executable:
chmod +x run_tests.sh
Run the script:
./run_tests.sh
Analyze the results:
If successful:
Compilation successful.
Running tests...
All tests passed successfully!
See test_results.log for details.
If there’s a failure:
Compilation successful.
Running tests...
Some tests failed. Check test_results.log for details.
5. Integrating with CI/CD
If you're using a CI/CD system (e.g., GitHub Actions, GitLab CI, Jenkins), you can integrate this workflow for automated testing after every code push.

Example: GitHub Actions

Create a .github/workflows/test.yml file:

name: Build and Test

on:
  push:
    branches:
      - main
  pull_request:

jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Install dependencies
        run: sudo apt-get install -y libmbedtls-dev

      - name: Run tests
        run: ./run_tests.sh
6. Summary of the Workflow
Compile:
Use the Makefile to compile the main program and tests.
Test:
Run the Seatest-based unit tests.
Log:
Record results in test_results.log.
Clean Up:
Remove compiled artifacts to keep the workspace clean.
Automate:
Use a CI/CD pipeline for continuous integration.
Would you like assistance with setting up specific test cases or integrating this workflow into your development process?
