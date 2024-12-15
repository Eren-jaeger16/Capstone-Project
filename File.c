/*Below are detailed suggestions and design options for evolving your current certificate exchange protocol into a more flexible, non-blocking 
(asynchronous) or state-machine-driven implementation. The goal is to decouple the raw I/O operations from the logic of sending/receiving certificates,
provide a clear structure for the protocol state, and allow the application to integrate the file transfer smoothly into event-driven or asynchronous frameworks.


Non-blocking I/O Support: Instead of waiting (blocking) for mbedtls_ssl_read() or mbedtls_ssl_write() to complete, allow the code to return immediately if it 
cannot proceed, and resume when more data is available or when the network is ready for writing. This can allow integration into event loops, select()/poll()-based I/O,
or asynchronous frameworks.
State Machine for Protocol Logic: Introduce a state machine to keep track of what part of the protocol you’re in. Instead of writing a large monolithic function that 
waits for each message (blocking), you keep track of a current state (e.g., "EXPECTING_CERT_INFO" or "SENDING_CHUNKS") and call a step function that attempts to do 
whatever is needed at that moment. If the I/O is not ready, you return and later resume from the same state.
Context Structure: Define a context structure that holds:
The current state of the protocol exchange.
Buffers for partial reads/writes.
The total size of the file to send/receive.
The amount of data already transferred.
A file descriptor or file pointer for the certificate file.
Possibly callback functions to notify the application when certain events occur (e.g., "transfer complete").
With this approach, the application can:

Check if more data is ready to be processed (non-blocking read).
Feed data into the state machine when it’s ready.
Move on to other tasks without being stuck waiting for the network.
Possible Approaches

1. Fully Asynchronous with Event Loop Integration
Concept:

You run a main event loop (e.g., select(), poll(), or epoll() on sockets) and whenever the TLS socket is readable or writable, you call a "process step" function of 
your state machine. The state machine tries to read or write what it needs and if it can’t proceed (e.g., mbedtls_ssl_read() returns MBEDTLS_ERR_SSL_WANT_READ), it 
just stops and returns control to the event loop.
How to Implement:

Context Structure (transfer_context_t):*/
typedef enum {
    STATE_IDLE,
    STATE_REQUEST_SENT,
    STATE_WAITING_CERT_INFO,
    STATE_RECEIVING_DATA,
    STATE_TRANSFER_COMPLETE,
    STATE_SENDING_INFO,
    STATE_SENDING_DATA
    // ... Add more states if needed
} transfer_state_t;

typedef struct {
    mbedtls_ssl_context *ssl;
    transfer_state_t state;
    FILE *file;
    uint32_t total_size;
    uint32_t bytes_transferred;
    uint8_t msg_type;
    uint8_t header[5]; 
    size_t header_bytes_read;  // how many bytes of header have we read/written so far
    size_t payload_bytes_read; // how many bytes of payload read/written so far
    uint32_t payload_length;
    uint8_t *payload_buffer;
    size_t payload_buffer_size;
    // You might also store callbacks or user data here
} transfer_context_t;
/*Non-blocking I/O Considerations: With mbedtls, you can use a non-blocking socket underneath. Typically, you set the underlying BIO (callback for send/recv) to return
MBEDTLS_ERR_SSL_WANT_READ or MBEDTLS_ERR_SSL_WANT_WRITE when the operation would block. Your state machine functions then detect these return values and simply return 
to the caller, which will later retry.
Step Function: Create a function like int transfer_step(transfer_context_t *ctx) that:
Looks at ctx->state.
Based on the state, tries to perform the next action (e.g., read the next message header, read payload, write next chunk of data).
If mbedtls_ssl_read() or mbedtls_ssl_write() returns a "want read/write" error, just return to the event loop. The state machine remains in the same state. Next time the
socket is ready, you call transfer_step() again.
When a state transition condition is met (e.g., finished reading CERT_INFO), move ctx->state to the next state (e.g., STATE_RECEIVING_DATA).
If completed (e.g., all data received), set ctx->state to STATE_TRANSFER_COMPLETE.
Advantages:
Integrates nicely with event-driven code.
No blocking waits; you can handle multiple connections simultaneously.
2. Synchronous Code With Internal State Machine
If you still want synchronous calls (e.g., a function that just "runs" the transfer and returns), you can still benefit from a state machine:

The main difference is that you loop over transfer_step() until it completes, and if there's a blocking call, you handle it in a controlled manner (possibly with timeouts).
The state machine logic is the same, but you keep calling transfer_step() in a loop until STATE_TRANSFER_COMPLETE or an error occurs.
This makes the code cleaner and more maintainable, as the logic of what to do next is not scattered but centralized in the state machine transitions.
3. Using Callbacks and an Event-Driven Interface
You could design a small "framework" around your file transfer protocol:

Register callbacks:*/
on_cert_info_received(total_size)
on_chunk_received(data, length)
on_transfer_complete()
on_error(error_code)
/*Your state machine code calls these callbacks when events occur. The application is then free to handle them asynchronously (e.g., store the data in memory, write to file,
notify the GUI, etc.). This approach naturally leads to a clean separation of concerns: the state machine knows about the protocol, while the application logic is in callbacks.
4. Ring Buffers or Queues for Data
If you want to avoid blocking on writes, you might use a send queue:

Maintain a buffer or queue of messages (headers + payloads) that you want to send.
The state machine tries to send whatever is at the front of the queue.
If it can’t send everything at once (non-blocking), it remembers how far it got. Next time transfer_step() is called and the socket is writable, it continues from there.
This approach can also be applied to reading. If mbedtls_ssl_read() only provides partial data, you store it in a buffer until you have the full header or payload, then process 
it. The state machine only transitions states when full messages have been accumulated.

5. Integrating with Other Protocols or Multiple Certificates
The state machine approach makes it easy to add complexity:

If you need to send multiple certificates in sequence:
Extend the state machine to handle a "send next file" state, or loop back to STATE_SENDING_INFO after completion of one transfer.
If you need to interleave other message types (e.g., "PAUSE", "RESUME", "CANCEL"), add states or handle these messages in the message parsing step, transitioning states accordingly.
6. Practical Steps to Implement
Define the State Machine States and Transitions:
For example:
STATE_IDLE: Haven’t started anything.
STATE_REQUEST_SENT: Client sent a request, waiting for CERT_INFO.
STATE_WAITING_CERT_INFO: About to read CERT_INFO header and payload.
STATE_RECEIVING_DATA: Reading CERT_DATA chunks until total_size is reached.
STATE_TRANSFER_COMPLETE: Done.
For the server:
STATE_IDLE (no request yet)
STATE_WAITING_REQUEST: reading REQUEST_CERT
STATE_SENDING_INFO: sending CERT_INFO
STATE_SENDING_DATA: sending all chunks
STATE_SENDING_COMPLETE: sending TRANSFER_COMPLETE
Write Helper Functions for Partial I/O:
Functions like read_bytes_nonblocking(ssl, buffer, length, &bytes_read_so_far) that attempt to read exactly length bytes into buffer, updating bytes_read_so_far each call. 
If incomplete, return a "would block" status. If complete, return success.
Similarly for writing: write_bytes_nonblocking(ssl, buffer, length, &bytes_written_so_far).
Handle Headers and Payloads in Steps:
Each message read consists of two steps: first read the 5-byte header (possibly in multiple partial reads), then read the payload. The state machine might have intermediate 
sub-states or just variables that track where you are (e.g., header_bytes_read < 5, etc.).
Return Control Early:
On MBEDTLS_ERR_SSL_WANT_READ or MBEDTLS_ERR_SSL_WANT_WRITE, immediately return from transfer_step() to let the event loop handle other tasks. The next call to transfer_step() 
(when conditions are right) will resume from the same state and partial read/write positions.
Example Pseudocode for a Step Function*/
int transfer_step(transfer_context_t *ctx) {
    int ret;
    switch (ctx->state) {
    case STATE_IDLE:
        // Maybe we need to initiate a request here
        ctx->state = STATE_REQUEST_SENT;
        // Fall through or break, depending on logic
        break;

    case STATE_REQUEST_SENT:
        // Waiting for CERT_INFO
        // Try to read header
        ret = read_bytes_nonblocking(ctx->ssl, ctx->header, 5, &ctx->header_bytes_read);
        if (ret == WANT_READ) {
            return WANT_READ; // can't proceed now
        } else if (ret < 0) {
            return ret; // error
        }
        if (ctx->header_bytes_read < 5) {
            return WANT_READ; // partial read
        }

        // Parse message type and length
        ctx->msg_type = ctx->header[0];
        ctx->payload_length = ntohl(*(uint32_t*)&ctx->header[1]);

        // Allocate payload buffer if needed
        if (ctx->payload_length > ctx->payload_buffer_size) {
            free(ctx->payload_buffer);
            ctx->payload_buffer = malloc(ctx->payload_length);
            ctx->payload_buffer_size = ctx->payload_length;
        }

        ctx->payload_bytes_read = 0;
        ctx->state = STATE_WAITING_CERT_INFO; // next step: read payload
        break;

    case STATE_WAITING_CERT_INFO:
        ret = read_bytes_nonblocking(ctx->ssl, ctx->payload_buffer, ctx->payload_length, &ctx->payload_bytes_read);
        if (ret == WANT_READ) {
            return WANT_READ;
        } else if (ret < 0) {
            return ret;
        }
        if (ctx->payload_bytes_read < ctx->payload_length) {
            return WANT_READ; // still reading
        }

        // Now we have full CERT_INFO
        // parse total size, etc.
        ctx->total_size = ...;

        ctx->bytes_transferred = 0;
        ctx->state = STATE_RECEIVING_DATA; // ready to receive data chunks
        break;

    case STATE_RECEIVING_DATA:
        // Similar logic: read next header, then next payload chunk
        // When done or TRANSFER_COMPLETE received, update state
        break;

    default:
        // Handle other states
        break;
    }

    return 0; // success or still working, no error
}
/*This pseudocode shows that in each step, you attempt exactly what’s needed next. If you cannot complete the operation because the socket is not ready, you return a 
special code (like WANT_READ), and the caller can wait and call again when ready. This approach decouples the protocol logic from the actual blocking nature of I/O.

In summary: To move from a blocking, linear implementation to a flexible, asynchronous or state-machine-driven one, you will:

Introduce a state machine with well-defined states.
Use a context structure to hold state, buffers, and progress indicators.
Implement partial read/write functions to handle non-blocking I/O.
Integrate these into an event-driven loop or repeatedly call a step function until completion.
Optionally, use callbacks or events to notify the application of progress and completion.
This gives you a robust, extensible architecture that can handle multiple simultaneous transfers, integrate into GUIs or servers handling many clients, and cleanly 
handle complex protocol logic.






You said:
Please detail the implementation of each approach, in code along with proper explanations

ChatGPT

**Thought about Asynchronous & Synchronous Implementations** for a couple of seconds
Below are detailed examples of how to refactor your current certificate-transfer protocol into more flexible architectures, both asynchronous and synchronous, using a 
state machine. We will provide code snippets and step-by-step explanations for each approach. You can mix and match ideas from these approaches depending on the constraints
and style of your project.

Important Note:
These are conceptual reference implementations. In practice, you will need to handle error cases, integrate with your actual I/O event loops, and potentially adapt function 
signatures. The code is intentionally simplified to illustrate the design patterns and state machine logic, rather than being a fully tested, production-ready code drop.

Common Foundations

Message Types and Protocol Basics
We start with the same message definitions and message structure as before:*/

#define MSG_REQUEST_CERT        0x01
#define MSG_CERT_INFO           0x02
#define MSG_CERT_DATA           0x03
#define MSG_TRANSFER_COMPLETE   0x04
/*Each message: 1-byte type, 4-byte length (network order), followed by payload of length bytes.

Non-blocking I/O Handling with mbedtls
For non-blocking I/O, you must set up the underlying socket in non-blocking mode and configure mbedtls BIO callbacks accordingly. When mbedtls_ssl_read() or mbedtls_ssl_write()
returns MBEDTLS_ERR_SSL_WANT_READ or MBEDTLS_ERR_SSL_WANT_WRITE, it means you must stop and wait for the socket to become readable/writable again before continuing.

You can define small helper functions for partial reads/writes:*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <mbedtls/ssl.h>

// Return values for our step functions:
#define TRANSFER_OK          0
#define TRANSFER_WANT_READ   1
#define TRANSFER_WANT_WRITE  2
#define TRANSFER_ERROR       -1

// This function tries to read 'needed' bytes into 'buf' from SSL.
// 'consumed' tracks how many bytes have been read so far.
// Returns:
// - TRANSFER_OK if complete
// - TRANSFER_WANT_READ if need more data
// - TRANSFER_ERROR on error
int read_bytes_nonblocking(mbedtls_ssl_context *ssl, uint8_t *buf, size_t needed, size_t *consumed) {
    while (*consumed < needed) {
        int ret = mbedtls_ssl_read(ssl, buf + (*consumed), needed - (*consumed));
        if (ret > 0) {
            *consumed += ret;
        } else if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
            return TRANSFER_WANT_READ;
        } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            return TRANSFER_WANT_WRITE;
        } else {
            return TRANSFER_ERROR;
        }
    }
    return TRANSFER_OK;
}

// Similar for writing:
int write_bytes_nonblocking(mbedtls_ssl_context *ssl, const uint8_t *buf, size_t needed, size_t *written) {
    while (*written < needed) {
        int ret = mbedtls_ssl_write(ssl, buf + (*written), needed - (*written));
        if (ret > 0) {
            *written += ret;
        } else if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
            return TRANSFER_WANT_READ;
        } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            return TRANSFER_WANT_WRITE;
        } else {
            return TRANSFER_ERROR;
        }
    }
    return TRANSFER_OK;
}
//1. Synchronous Code with an Internal State Machine

//Even in a synchronous approach, using a state machine makes the code cleaner and more modular. The difference here is that we will just loop until we finish or encounter 
//an error, and we assume blocking I/O for simplicity. If read/write can block, that’s acceptable for this scenario. You can also integrate timeouts.

//State Definition
typedef enum {
    STATE_IDLE,
    STATE_REQUEST_SENT,
    STATE_WAITING_CERT_INFO,
    STATE_RECEIVING_DATA,
    STATE_TRANSFER_COMPLETE
} transfer_state_t;

typedef struct {
    mbedtls_ssl_context *ssl;
    transfer_state_t state;
    FILE *file;
    uint8_t header[5];
    size_t header_bytes_read;
    uint8_t *payload;
    size_t payload_len;
    size_t payload_bytes_read;
    uint32_t total_size;
    uint32_t bytes_received;
    int done;
} transfer_context_t;
//Step Function (Synchronous)
int transfer_step(transfer_context_t *ctx) {
    int ret;
    switch (ctx->state) {
    case STATE_REQUEST_SENT:
        // Need to read CERT_INFO header
        if (ctx->header_bytes_read < 5) {
            // blocking read
            ret = mbedtls_ssl_read(ctx->ssl, ctx->header + ctx->header_bytes_read, 5 - ctx->header_bytes_read);
            if (ret <= 0) {
                return TRANSFER_ERROR; // handle errors
            }
            ctx->header_bytes_read += ret;
            if (ctx->header_bytes_read < 5) {
                return TRANSFER_OK; // still waiting, but blocking is allowed
            }
        }

        // Parse CERT_INFO header
        if (ctx->header[0] != MSG_CERT_INFO) {
            return TRANSFER_ERROR;
        }
        uint32_t net_len;
        memcpy(&net_len, ctx->header + 1, 4);
        ctx->payload_len = ntohl(net_len);

        ctx->payload = malloc(ctx->payload_len);
        ctx->payload_bytes_read = 0;
        ctx->state = STATE_WAITING_CERT_INFO;
        // fall through to handle reading payload

    case STATE_WAITING_CERT_INFO:
        while (ctx->payload_bytes_read < ctx->payload_len) {
            // blocking read
            ret = mbedtls_ssl_read(ctx->ssl, ctx->payload + ctx->payload_bytes_read,
                                   ctx->payload_len - ctx->payload_bytes_read);
            if (ret <= 0) {
                return TRANSFER_ERROR; 
            }
            ctx->payload_bytes_read += ret;
        }

        // Parse CERT_INFO payload
        memcpy(&net_len, ctx->payload, 4);
        ctx->total_size = ntohl(net_len);
        free(ctx->payload); 
        ctx->payload = NULL;

        ctx->bytes_received = 0;
        ctx->header_bytes_read = 0; // reset for next message
        ctx->state = STATE_RECEIVING_DATA;
        return TRANSFER_OK; // next call will proceed to receive data

    case STATE_RECEIVING_DATA:
        // Repeatedly read headers and payload for CERT_DATA
        // ... blocking logic: read header, parse length, read payload chunk,
        // write to file until TRANSFER_COMPLETE is encountered.
        // Once done:
        ctx->state = STATE_TRANSFER_COMPLETE;
        ctx->done = 1;
        return TRANSFER_OK;

    default:
        return TRANSFER_OK;
    }
}
Explanation:

/*Each call to transfer_step() tries to make progress. In a synchronous model, you might call transfer_step() in a loop until ctx->done is set.
The logic is structured by states, making the code easier to follow than a single monolithic function.
2. Asynchronous with Event Loop Integration

In this approach, we do not block. Instead, transfer_step() returns TRANSFER_WANT_READ or TRANSFER_WANT_WRITE when it needs more I/O. The event 
loop (e.g., using select()/poll()) will re-invoke transfer_step() when the socket is ready.

State Definition (Similar to Above)
We use a similar context, but we rely heavily on partial read/write functions:*/

typedef enum {
    STATE_IDLE,
    STATE_REQUEST_SENT,
    STATE_WAITING_CERT_INFO_HEADER,
    STATE_WAITING_CERT_INFO_PAYLOAD,
    STATE_RECEIVING_CHUNKS,
    STATE_WAITING_CHUNK_HEADER,
    STATE_WAITING_CHUNK_DATA,
    STATE_TRANSFER_COMPLETE
} transfer_state_t;

typedef struct {
    mbedtls_ssl_context *ssl;
    transfer_state_t state;
    FILE *file;
    uint8_t header[5];
    size_t header_bytes_read;
    uint8_t *payload;
    size_t payload_len;
    size_t payload_bytes_read;
    uint32_t total_size;
    uint32_t bytes_received;
    int completed;
} transfer_context_t;
Non-blocking Step Function
int transfer_step(transfer_context_t *ctx) {
    int ret;

    switch (ctx->state) {
    case STATE_REQUEST_SENT:
        // We expect CERT_INFO header next
        ctx->header_bytes_read = 0;
        ctx->state = STATE_WAITING_CERT_INFO_HEADER;
        // fall through

    case STATE_WAITING_CERT_INFO_HEADER:
        ret = read_bytes_nonblocking(ctx->ssl, ctx->header, 5, &ctx->header_bytes_read);
        if (ret != TRANSFER_OK) {
            return ret; // WANT_READ/WRITE or ERROR
        }

        if (ctx->header[0] != MSG_CERT_INFO) {
            return TRANSFER_ERROR;
        }

        uint32_t net_len;
        memcpy(&net_len, ctx->header + 1, 4);
        ctx->payload_len = ntohl(net_len);
        ctx->payload = realloc(ctx->payload, ctx->payload_len);
        ctx->payload_bytes_read = 0;
        ctx->state = STATE_WAITING_CERT_INFO_PAYLOAD;
        // fall through

    case STATE_WAITING_CERT_INFO_PAYLOAD:
        ret = read_bytes_nonblocking(ctx->ssl, ctx->payload, ctx->payload_len, &ctx->payload_bytes_read);
        if (ret != TRANSFER_OK) {
            return ret;
        }
        // Parse CERT_INFO payload
        uint32_t net_size;
        memcpy(&net_size, ctx->payload, 4);
        ctx->total_size = ntohl(net_size);
        free(ctx->payload);
        ctx->payload = NULL;

        ctx->bytes_received = 0;
        // Now move to receiving chunks
        ctx->state = STATE_WAITING_CHUNK_HEADER;
        ctx->header_bytes_read = 0;
        return TRANSFER_OK;

    case STATE_WAITING_CHUNK_HEADER:
        ret = read_bytes_nonblocking(ctx->ssl, ctx->header, 5, &ctx->header_bytes_read);
        if (ret != TRANSFER_OK) {
            return ret;
        }
        // Parse the header
        if (ctx->header[0] == MSG_TRANSFER_COMPLETE) {
            ctx->state = STATE_TRANSFER_COMPLETE;
            ctx->completed = 1;
            return TRANSFER_OK;
        }

        if (ctx->header[0] != MSG_CERT_DATA) {
            return TRANSFER_ERROR;
        }

        memcpy(&net_len, ctx->header + 1, 4);
        ctx->payload_len = ntohl(net_len);
        ctx->payload = realloc(ctx->payload, ctx->payload_len);
        ctx->payload_bytes_read = 0;
        ctx->state = STATE_WAITING_CHUNK_DATA;
        return TRANSFER_OK;

    case STATE_WAITING_CHUNK_DATA:
        ret = read_bytes_nonblocking(ctx->ssl, ctx->payload, ctx->payload_len, &ctx->payload_bytes_read);
        if (ret != TRANSFER_OK) {
            return ret;
        }
        // Write chunk to file
        fwrite(ctx->payload, 1, ctx->payload_len, ctx->file);
        ctx->bytes_received += ctx->payload_len;

        // Wait for next chunk header
        ctx->state = STATE_WAITING_CHUNK_HEADER;
        ctx->header_bytes_read = 0;
        return TRANSFER_OK;

    case STATE_TRANSFER_COMPLETE:
        // Do nothing, we’re done
        return TRANSFER_OK;

    default:
        return TRANSFER_OK;
    }
}
/*Explanation:

Each call tries to advance the state machine as far as possible.
If more data is needed from the network and is not available, the function returns TRANSFER_WANT_READ or TRANSFER_WANT_WRITE. Your event loop can then 
wait for the socket to be ready and call transfer_step() again.
The logic is broken down into small states, each representing a precise step in the protocol parsing.
3. Using Callbacks and Events

Instead of the main logic directly reading/writing files, you can use callbacks to notify the application layer of events. For example:*/

typedef struct {
    void (*on_cert_info)(void *user_data, uint32_t total_size);
    void (*on_chunk)(void *user_data, const uint8_t *data, size_t length);
    void (*on_complete)(void *user_data);
    void (*on_error)(void *user_data, int error_code);
    void *user_data;
    // Same fields as before for state tracking...
} transfer_context_t;
/*In transfer_step(), whenever CERT_INFO is fully read, call ctx->on_cert_info(user_data, total_size). For each CERT_DATA chunk, 
call ctx->on_chunk(user_data, data, length). Upon completion, call ctx->on_complete(user_data). On errors, ctx->on_error.

This decouples the transfer logic from the file writing. The application might store chunks in memory, write them to disk asynchronously, or process 
them differently.

4. Integrating with a Real Event Loop

If you’re using select() or poll(), your main loop might look like this:*/

// Pseudocode
while (!ctx->completed) {
    fd_set read_fds, write_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);

    // If last return was WANT_READ, watch for readable
    FD_SET(ssl_fd, &read_fds);
    // If WANT_WRITE, watch for writable
    // If OK, just watch read (if reading) or write (if sending)

    select(...);

    int ret = transfer_step(ctx);
    if (ret == TRANSFER_ERROR) {
        // Handle error
        break;
    } else if (ret == TRANSFER_WANT_READ) {
        // Next iteration, wait for readable
    } else if (ret == TRANSFER_WANT_WRITE) {
        // Next iteration, wait for writable
    }
}

// Once complete, close file, clean up
/*Explanation:

The event loop waits until the underlying socket is ready.
When ready, transfer_step() tries to make progress.
If it can’t proceed due to lack of data (WANT_READ) or inability to write (WANT_WRITE), control returns to the event loop to wait again.
Summary

Synchronous with State Machine:
We showed how to break the logic into states, even if the code blocks on I/O. This makes the code more maintainable and easier to extend.
Asynchronous/Non-Blocking:
We introduced partial read/write helpers and extended the state machine to return early when the operation would block. This allows integration 
with event loops and asynchronous frameworks.
Callbacks and Events:
Using callbacks decouples the data handling (like file writes) from the protocol state machine. It’s a clean architecture for larger systems.
Event Loop Integration:
We demonstrated how you might integrate the asynchronous step function into an event loop with select() or poll().
By combining these patterns, you can tailor the solution to your needs. For instance, you might implement a non-blocking state machine with 
callbacks for a GUI application, or a synchronous state machine for a simple command-line tool. The key idea is to separate protocol state management
from raw I/O operations and application logic, leading to cleaner, more modular, and more flexible code.*/


/*The issue you’re encountering is most likely due to the switch case “fall-through” behavior in C. 
In a switch statement, if you do not explicitly use a break; (or another terminating statement 
like return) at the end of a case, execution will continue into the next case block.

In your code, each case in the switch looks like this:*/

switch (ctx->state) {

case EXCH_STATE_IDLE:
    if (request_cert(&ctx->ssl) == 1) {
        ctx->state = EXCH_STATE_CERT_REQUESTED;
        return 1;
    }
    // No break here, so execution continues directly to EXCH_STATE_CERT_REQUESTED

case EXCH_STATE_CERT_REQUESTED:
    printf("%d\n", receive_cert(&ctx->ssl, ctx->save_path));
    if (receive_cert(&ctx->ssl, ctx->save_path) == 1) {
        printf("%d\n", receive_cert(&ctx->ssl, ctx->save_path));
        ctx->state = EXCH_STATE_CERT_RECEIVED;
        return 1;
    }
    // No break here, so execution continues directly to EXCH_STATE_CERT_RECEIVED

case EXCH_STATE_CERT_RECEIVED:
    if ((send_ack(&ctx->ssl)) == 1 && (send_cert_response(&ctx->ssl, ctx->cert_path) == 1)) {
        ctx->state = EXCH_STATE_CERT_EXCHANGED;
        return 1;
    }
    // No break here, so it will continue to the next case if not returned

case EXCH_STATE_CERT_EXCHANGED:
    if (receive_ack(&ctx->ssl) == 1) {
        ctx->done = 1;
        return 1;
    }
    // No break here either
}
What this means is:

/*If EXCH_STATE_IDLE doesn’t cause a return, execution will fall through and attempt EXCH_STATE_CERT_REQUESTED logic.
If EXCH_STATE_CERT_REQUESTED doesn’t cause a return, it falls through to EXCH_STATE_CERT_RECEIVED, and so on.
Because your code doesn't have break; statements, when receive_cert() returns 0 in EXCH_STATE_CERT_REQUESTED, 
the code continues into the EXCH_STATE_CERT_RECEIVED block—executing code that it shouldn’t.

How to Fix It:

Add break; statements at the end of each case block if you do not want to fall through. For example:*/
switch (ctx->state) {

case EXCH_STATE_IDLE:
    if (request_cert(&ctx->ssl) == 1) {
        ctx->state = EXCH_STATE_CERT_REQUESTED;
        return 1;
    }
    break; // Stop fall-through if no return

case EXCH_STATE_CERT_REQUESTED:
    printf("%d\n", receive_cert(&ctx->ssl, ctx->save_path));
    if (receive_cert(&ctx->ssl, ctx->save_path) == 1) {
        printf("%d\n", receive_cert(&ctx->ssl, ctx->save_path));
        ctx->state = EXCH_STATE_CERT_RECEIVED;
        return 1;
    }
    break; // Stop fall-through

case EXCH_STATE_CERT_RECEIVED:
    if ((send_ack(&ctx->ssl)) == 1 && (send_cert_response(&ctx->ssl, ctx->cert_path) == 1)) {
        ctx->state = EXCH_STATE_CERT_EXCHANGED;
        return 1;
    }
    break; // Stop fall-through

case EXCH_STATE_CERT_EXCHANGED:
    if (receive_ack(&ctx->ssl) == 1) {
        ctx->done = 1;
        return 1;
    }
    break; // Stop fall-through

default:
    break;
}

/*Consider storing the result of receive_cert() in a variable if you need to print and check it more
than once, rather than calling the function multiple times. Each function call might change state or
consume data:*/

int res = receive_cert(&ctx->ssl, ctx->save_path);
printf("%d\n", res);
if (res == 1) {
    // ...
}
/*By adding break; statements and ensuring that functions are not called multiple times unnecessarily,
    you should prevent unintended code execution and ensure the switch handles states as intended.*/
