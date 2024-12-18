//This function retrieves the local time, date, and time zone from the system.

//Code (Platform-Independent C)

#include <stdio.h>
#include <time.h>
#include <string.h>

typedef struct {
    char datetime[32];  // Format: YYYY-MM-DD HH:MM:SS
    char timezone[8];   // Format: UTC+HH:MM or UTC-HH:MM
} TimeInfo;

void get_local_time(TimeInfo *time_info) {
    time_t now = time(NULL);
    struct tm local_time;
    char timezone[8];

#ifdef _WIN32
    localtime_s(&local_time, &now);
#else
    localtime_r(&now, &local_time);
#endif

    // Format local time and date
    strftime(time_info->datetime, sizeof(time_info->datetime), "%Y-%m-%d %H:%M:%S", &local_time);

    // Get time zone offset
    long timezone_offset = local_time.tm_gmtoff / 60; // Offset in minutes
    int hours = timezone_offset / 60;
    int minutes = abs(timezone_offset % 60);

    snprintf(time_info->timezone, sizeof(time_info->timezone), "UTC%+03d:%02d", hours, minutes);
}
//2. Send Time Information
//To send the retrieved TimeInfo structure over a TLS connection:

//Code

void send_time_info(mbedtls_ssl_context *ssl) {
    TimeInfo time_info;
    get_local_time(&time_info);

    // Prepare message
    uint8_t buffer[64];
    uint8_t *ptr = buffer;

    // Copy datetime (32 bytes max) and timezone (8 bytes max)
    memset(buffer, 0, sizeof(buffer));
    memcpy(ptr, time_info.datetime, sizeof(time_info.datetime));
    ptr += sizeof(time_info.datetime);
    memcpy(ptr, time_info.timezone, sizeof(time_info.timezone));

    // Send the data over TLS
    if (mbedtls_ssl_write(ssl, buffer, sizeof(buffer)) <= 0) {
        perror("Error sending time information");
        exit(EXIT_FAILURE);
    }

    printf("Time information sent: %s %s\n", time_info.datetime, time_info.timezone);
}
//3. Receive Time Information
//The receiving function parses the incoming data and applies the time and time zone on the embedded Linux device.

//Code

#include <stdlib.h>

void receive_and_set_time(mbedtls_ssl_context *ssl) {
    uint8_t buffer[64];
    TimeInfo received_time_info;

    // Read time info
    if (mbedtls_ssl_read(ssl, buffer, sizeof(buffer)) <= 0) {
        perror("Error receiving time information");
        exit(EXIT_FAILURE);
    }

    // Extract datetime and timezone
    memcpy(received_time_info.datetime, buffer, sizeof(received_time_info.datetime));
    memcpy(received_time_info.timezone, buffer + sizeof(received_time_info.datetime), sizeof(received_time_info.timezone));

    printf("Time received: %s %s\n", received_time_info.datetime, received_time_info.timezone);

    // Apply time and timezone on the system
    char command[128];

    // Set system time
    snprintf(command, sizeof(command), "date -s \"%s\"", received_time_info.datetime);
    if (system(command) != 0) {
        perror("Failed to set system time");
    }

    // Set timezone
    snprintf(command, sizeof(command), "timedatectl set-timezone %s", received_time_info.timezone);
    if (system(command) != 0) {
        perror("Failed to set system timezone");
    }
}
/*4. Integration
On the sender, call send_time_info after establishing the TLS connection.
On the receiver, call receive_and_set_time after receiving the TLS connection.
Testing
Ensure the sender machine has the correct local time and timezone.
Verify that the receiver correctly sets the system time and timezone.
Considerations
Ensure the device running embedded Linux has timedatectl or date command available.
If manual system command execution isn't allowed, use the Linux settimeofday and timezone system calls for more direct control.
Would you like me to extend this with examples of direct system calls (e.g., settimeofday) for embedded systems?*/

/*These issues suggest a combination of subtle bugs in your non-blocking implementation.
Let's debug each issue systematically:

1. State Called One Extra Time and No Data Received
Root Cause

Non-blocking socket behavior: When you call mbedtls_ssl_read, it may return MBEDTLS_ERR_SSL_WANT_READ
even if the data has been partially read or not yet fully processed.
If the client state is not correctly advanced after processing the message, it can loop back and retry 
unnecessarily.
Solution

Ensure State Transitions Happen Correctly:
Transition to the next state only after a message is completely received and processed.
Track the number of bytes read for CERT_RESP and wait until all expected bytes are received before transitioning.
Track Partial Reads:
Update the protocol structure to include a bytes_received field to accumulate partial data.
Modified Code (WAIT_FOR_CERT_RESP)*/

case WAIT_FOR_CERT_RESP: {
    ret = mbedtls_ssl_read(protocol->ssl, protocol->buffer + protocol->bytes_received, sizeof(protocol->buffer) - protocol->bytes_received);

    if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
        break; // Non-blocking: no new data, retry later
    } else if (ret <= 0) {
        printf("Error receiving CERT_RESP: -0x%04x\n", -ret);
        exit(EXIT_FAILURE);
    }

    // Accumulate received data
    protocol->bytes_received += ret;

    // Check if we have at least the header
    if (protocol->bytes_received >= 5) {
        // Extract payload size from header
        uint32_t payload_size;
        memcpy(&payload_size, &protocol->buffer[1], sizeof(payload_size));
        payload_size = ntohl(payload_size);

        // Check if we have the full payload
        if (protocol->bytes_received >= 5 + payload_size) {
            // Process the certificate
            printf("CERT_RESP received. Payload size: %u bytes.\n", payload_size);
            FILE *file = fopen("received_cert.pem", "wb");
            if (!file) {
                perror("Error opening file to save certificate");
                exit(EXIT_FAILURE);
            }
            fwrite(protocol->buffer + 5, 1, payload_size, file);
            fclose(file);
            printf("Certificate saved to 'received_cert.pem'.\n");

            protocol->state = SEND_ACK; // Transition to the next state
            protocol->bytes_received = 0; // Reset for next read
        }
    }
    break;
}
/*2. Receiving a Series of Wrong Messages
Root Cause

Protocol desynchronization: If the mbedtls_ssl_read function reads data from the socket after a protocol 
message, subsequent calls may misinterpret leftover data in the buffer as a valid protocol message.
This could occur if the server sends extra data or if the client processes incomplete messages.
Solution

Flush the Buffer:
Ensure that the buffer only contains meaningful protocol messages.
Discard unexpected or extra bytes.
Validate Message Format:
Add strict validation for message structure (e.g., correct header and payload size).
Modified Code for Buffer Validation:*/
if (protocol->buffer[0] != CERT_RESP) {
    printf("Unexpected message type: 0x%02x\n", protocol->buffer[0]);

    // Discard the rest of the buffer
    protocol->bytes_received = 0;
    break; // Retry later
}
/*Ensure Server Doesn't Send Extra Data:
Verify that the server sends only one CERT_RESP message and stops until the client sends ACK.
3. Wireshark Shows TCP ACKs but No TLS Processing
Root Cause

The client receives the TLS certificate message, but it’s not fully processed because:
Partial Reads: mbedtls_ssl_read returns before consuming the entire payload.
Buffer Misalignment: The data in the buffer is misinterpreted.
Solution

Implement partial read handling as shown in Solution 1.
Validate that all expected bytes of the message (header + payload) are fully received before processing.
4. Debugging Strategy
Add Debug Logs:
Log the size of data read by mbedtls_ssl_read and track protocol->bytes_received.
printf("Read %d bytes. Total received: %zu bytes.\n", ret, protocol->bytes_received);
Log TLS Errors:
Convert mbedtls errors into readable text:
char error_buf[100];*/
mbedtls_strerror(ret, error_buf, sizeof(error_buf));
printf("TLS error: %s\n", error_buf);
//Analyze Wireshark Captures:
//Verify the server sends exactly one CERT_RESP.
//Confirm the client’s TCP ACKs align with the server’s data.
//Refinements
//Client Protocol Structure

//Add fields for tracking partial reads:

typedef struct {
    ClientState state;
    mbedtls_ssl_context *ssl;
    uint8_t buffer[1024];
    size_t bytes_received; // Tracks how much of the current message has been received
} ClientProtocol;
Retry on Failure

Instead of exiting on unexpected messages, retry the operation or flush the buffer:

if (protocol->buffer[0] != CERT_RESP) {
    printf("Unexpected message type: 0x%02x. Discarding buffer and retrying.\n", protocol->buffer[0]);
    protocol->bytes_received = 0; // Discard invalid data
    break; // Retry later
}
/*Testing and Debugging
Instrument Code:
Log all received data and its size for troubleshooting:*/
printf("Received data: ");
for (size_t i = 0; i < ret; i++) {
    printf("%02x ", protocol->buffer[i]);
}
printf("\n");
/*Simulate Failure Scenarios:
Test with a deliberately misbehaving server (e.g., sends extra data or incomplete messages).
Run Wireshark:
Verify message boundaries match your protocol's expectations.
Expected Outcome
After implementing the fixes:

The client processes the certificate without errors.
The CERT_RESP message is properly validated and saved.
No desynchronization occurs due to unexpected or extra data.
The state machine transitions smoothly without extra loops.
Would you like help analyzing specific Wireshark captures or debugging further?*/






/*You said:
What you suggested : 
"if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
        break; // Non-blocking: no new data, retry later
    } else if (ret <= 0) {
        printf("Error receiving CERT_RESP: -0x%04x\n", -ret);
        exit(EXIT_FAILURE);
    }"

I already have it in my code, it breaks 8 times because of MBEDTLS_ERR_SSL_WANT_READ and then starts
receiving wrong messages
ChatGPT said:

ChatGPT
Thank you for clarifying. Since the issue persists even with the MBEDTLS_ERR_SSL_WANT_READ handling, it
    seems there’s a deeper problem related to how the client handles incomplete data and interprets the 
incoming buffer.

Here’s a systematic approach to debugging and resolving this issue.

Key Issues
Why Does It Break 8 Times?
The mbedtls_ssl_read function returns MBEDTLS_ERR_SSL_WANT_READ because the server has not yet sent 
enough data, or the socket is not ready.
The break avoids blocking but does not address why the data is delayed.
Likely Causes:

The server may be delaying its response or sending it in smaller chunks than expected.
The client may not be properly handling fragmented messages or incomplete reads.
Why Are the Messages Wrong (0x2d, 0x42, etc.)?
This indicates a desynchronization issue. After reading part of the message, the client misinterprets 
subsequent data due to:
A corrupted or incomplete buffer.
The client attempting to read before the server finishes sending.
Key Observation from Wireshark:

If Wireshark shows the certificate being sent correctly and TCP acknowledgments occurring, the issue lies
in how the client processes and validates the received data.
Comprehensive Fix
1. Handle Partial Reads Correctly

Instead of assuming a single mbedtls_ssl_read call will receive the complete message (header + payload), 
accumulate the data in a buffer until the full message is received.

Modify the WAIT_FOR_CERT_RESP state as follows:*/

case WAIT_FOR_CERT_RESP: {
    // Attempt to read more data
    ret = mbedtls_ssl_read(protocol->ssl, protocol->buffer + protocol->bytes_received, sizeof(protocol->buffer) - protocol->bytes_received);

    if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
        break; // Non-blocking: no new data, retry later
    } else if (ret <= 0) {
        printf("Error receiving CERT_RESP: -0x%04x\n", -ret);
        exit(EXIT_FAILURE);
    }

    // Accumulate received data
    protocol->bytes_received += ret;

    // Process the header if enough data is available
    if (protocol->bytes_received >= 5) {
        // Extract payload size from the header
        uint32_t payload_size;
        memcpy(&payload_size, &protocol->buffer[1], sizeof(payload_size));
        payload_size = ntohl(payload_size);

        // Ensure the full payload is received
        if (protocol->bytes_received >= 5 + payload_size) {
            printf("CERT_RESP received. Payload size: %u bytes.\n", payload_size);

            // Save the certificate to a file
            FILE *file = fopen("received_cert.pem", "wb");
            if (!file) {
                perror("Error opening file to save certificate");
                exit(EXIT_FAILURE);
            }
            fwrite(protocol->buffer + 5, 1, payload_size, file);
            fclose(file);

            printf("Certificate saved to 'received_cert.pem'.\n");

            // Transition to the next state
            protocol->state = SEND_ACK;
            protocol->bytes_received = 0; // Reset for next read
        }
    }
    break;
}
//2. Validate Incoming Data

//To ensure no unexpected or corrupt data is processed:

//Check the message type (protocol->buffer[0]).
//Validate the payload size extracted from the header.
if (protocol->buffer[0] != CERT_RESP) {
    printf("Unexpected message type: 0x%02x. Discarding buffer.\n", protocol->buffer[0]);
    protocol->bytes_received = 0; // Reset buffer
    break; // Retry later
}
//3. Debug Unexpected Data

//If the wrong message types (0x2d, 0x42, etc.) continue:

//Log the Buffer Content: Add debug logs to print the raw buffer content before interpreting it.
printf("Raw buffer content: ");
for (size_t i = 0; i < protocol->bytes_received; i++) {
    printf("%02x ", protocol->buffer[i]);
}
printf("\n");
/*Check Server Behavior: Ensure the server:
Sends a single CERT_RESP message.
Does not send unexpected extra data.
Verify Wireshark Captures:
Confirm the message sequence matches your expectations.
Look for signs of retransmissions or fragmentation.
4. Ensure Server Completes Writes

On the server side, ensure the mbedtls_ssl_write call for CERT_RESP sends the complete message before moving on:*/

while (bytes_sent < total_bytes_to_send) {
    ret = mbedtls_ssl_write(ssl, buffer + bytes_sent, total_bytes_to_send - bytes_sent);
    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        continue; // Retry until complete
    } else if (ret <= 0) {
        printf("Error sending CERT_RESP: -0x%04x\n", -ret);
        exit(EXIT_FAILURE);
    }
    bytes_sent += ret;
}
/*Key Debugging Steps
Instrument Logging:
Log mbedtls_ssl_read return values and accumulated bytes_received.
Print the buffer content and header details.
Check Message Boundaries:
Ensure the client waits until the full message (header + payload) is received before processing.
Verify Server Behavior:
Ensure the server sends a single, properly formatted CERT_RESP message.
Wireshark Validation:
Confirm the client acknowledges the complete TLS record containing CERT_RESP.
Expected Outcome
After implementing the fixes:

The client correctly handles partial reads and validates message types.
The desynchronization issue (unexpected messages like 0x2d, 0x42, etc.) is resolved.
The protocol works consistently, transitioning smoothly through all states.
Let me know if you encounter further issues, and we can debug together!*/






/*You said:
Great thanks, I need you to provide me with all cleanup and retry mechanisms possible, in case at any
point something fails and it need to be started all over again. 
Also, expand the protocol to include timeouts
ChatGPT said:

ChatGPT
Here's a comprehensive approach to include cleanup and retry mechanisms, as well as timeouts, in your 
non-blocking TLS client implementation. This ensures robust error handling and allows the client to retry 
or restart if something fails.

Cleanup Mechanisms
Add a cleanup function to properly reset the protocol and free resources in case of failure. This ensures
no memory leaks or dangling pointers.

Client Cleanup Function*/

void client_cleanup(ClientProtocol *protocol) {
    // Reset state
    protocol->state = HANDSHAKE_INIT;
    protocol->bytes_received = 0;

    // Clear buffer
    memset(protocol->buffer, 0, sizeof(protocol->buffer));

    // Cleanup SSL context
    if (protocol->ssl) {
        mbedtls_ssl_session_reset(protocol->ssl);
    }

    printf("Protocol state reset. Ready to retry.\n");
}
/*Retry Mechanisms
Introduce retry counters to limit how many times the client can retry the handshake or protocol states. If
    retries are exceeded, log the error and terminate.

Retry Parameters

Define retry limits and counters in the ClientProtocol structure:*/

#define MAX_RETRIES 3

typedef struct {
    ClientState state;
    mbedtls_ssl_context *ssl;
    uint8_t buffer[1024];
    size_t bytes_received;
    int retries; // Retry counter
    int timeout_ms; // Timeout for the current operation
    int elapsed_time; // Time elapsed for the current state
} ClientProtocol;
//Retry Logic in the State Machine

//Modify the state machine to handle retries:

case HANDSHAKE_PROCESS:
    ret = mbedtls_ssl_handshake(protocol->ssl);
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        protocol->elapsed_time += 50; // Assuming 50ms polling interval
        if (protocol->elapsed_time >= protocol->timeout_ms) {
            printf("Handshake timed out. Retrying...\n");
            protocol->retries++;
            if (protocol->retries >= MAX_RETRIES) {
                printf("Max retries reached. Aborting.\n");
                client_cleanup(protocol);
                exit(EXIT_FAILURE);
            }
            protocol->state = HANDSHAKE_INIT; // Retry handshake
            protocol->elapsed_time = 0;
        }
        break; // Retry later
    } else if (ret != 0) {
        printf("TLS handshake failed: -0x%04x. Retrying...\n", -ret);
        protocol->retries++;
        if (protocol->retries >= MAX_RETRIES) {
            printf("Max retries reached. Aborting.\n");
            client_cleanup(protocol);
            exit(EXIT_FAILURE);
        }
        protocol->state = HANDSHAKE_INIT;
        protocol->elapsed_time = 0;
        break;
    }
    printf("TLS handshake completed.\n");
    protocol->state = SEND_CERT_REQ;
    protocol->retries = 0;
    protocol->elapsed_time = 0;
    break;
/*Timeouts
Add timeouts to each state to ensure the client does not hang indefinitely. Use the elapsed_time field
in the protocol structure to track how long the client has been in the current state.

Timeout Parameters

Define timeouts for each state:*/

#define HANDSHAKE_TIMEOUT 5000 // 5 seconds
#define CERT_RESP_TIMEOUT 3000 // 3 seconds
#define ACK_TIMEOUT 2000       // 2 seconds
//Timeout Logic in State Machine

//Update each state to include timeout checks:

case WAIT_FOR_CERT_RESP:
    ret = mbedtls_ssl_read(protocol->ssl, protocol->buffer + protocol->bytes_received, sizeof(protocol->buffer) - protocol->bytes_received);
    if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
        protocol->elapsed_time += 50; // Assuming 50ms polling interval
        if (protocol->elapsed_time >= protocol->timeout_ms) {
            printf("WAIT_FOR_CERT_RESP timed out. Retrying...\n");
            protocol->retries++;
            if (protocol->retries >= MAX_RETRIES) {
                printf("Max retries reached. Aborting.\n");
                client_cleanup(protocol);
                exit(EXIT_FAILURE);
            }
            protocol->state = SEND_CERT_REQ; // Retry by resending CERT_REQ
            protocol->elapsed_time = 0;
        }
        break; // Retry later
    } else if (ret <= 0) {
        printf("Error receiving CERT_RESP: -0x%04x. Retrying...\n", -ret);
        protocol->retries++;
        if (protocol->retries >= MAX_RETRIES) {
            printf("Max retries reached. Aborting.\n");
            client_cleanup(protocol);
            exit(EXIT_FAILURE);
        }
        protocol->state = SEND_CERT_REQ; // Retry by resending CERT_REQ
        protocol->elapsed_time = 0;
        break;
    }

    protocol->bytes_received += ret;
    if (protocol->bytes_received >= 5) {
        uint32_t payload_size;
        memcpy(&payload_size, &protocol->buffer[1], sizeof(payload_size));
        payload_size = ntohl(payload_size);

        if (protocol->bytes_received >= 5 + payload_size) {
            FILE *file = fopen("received_cert.pem", "wb");
            fwrite(protocol->buffer + 5, 1, payload_size, file);
            fclose(file);

            printf("Certificate saved to 'received_cert.pem'.\n");
            protocol->state = SEND_ACK;
            protocol->bytes_received = 0;
            protocol->elapsed_time = 0;
        }
    }
    break;
/*Reset Timeout and Retry Counters
Whenever a state successfully completes, reset the timeout and retry counters:*/

protocol->elapsed_time = 0;
protocol->retries = 0;
/*Summary of Changes
Cleanup:
Reset the protocol state, buffer, and SSL session using client_cleanup.
Ensure resources are properly freed on failure.
Retries:
Add retry counters (retries) to limit the number of attempts for each state.
Reset retries on successful transitions.
Timeouts:
Add timeout_ms and elapsed_time fields to track state durations.
Abort or retry the current state if the timeout is exceeded.
Example Initialization
Initialize the protocol with appropriate timeouts:*/

void initialize_client_protocol(ClientProtocol *protocol, mbedtls_ssl_context *ssl) {
    protocol->state = HANDSHAKE_INIT;
    protocol->ssl = ssl;
    memset(protocol->buffer, 0, sizeof(protocol->buffer));
    protocol->bytes_received = 0;
    protocol->retries = 0;
    protocol->timeout_ms = HANDSHAKE_TIMEOUT;
    protocol->elapsed_time = 0;
}
/*Testing
Simulate Failures:
Test with a misbehaving server (e.g., delayed responses or incorrect messages).
Test with network delays to ensure the timeout logic works.
Wireshark Validation:
Confirm that retries and timeouts behave as expected in the packet trace.
Would you like further guidance on testing or adding specific recovery scenarios?*/






/*You said:
please guide me on thorough testing
ChatGPT said:

ChatGPT
Thorough testing ensures your implementation handles all edge cases and failure 
scenarios gracefully. Here's a structured guide for testing your non-blocking TLS client and protocol:

1. Set Up the Environment
Tools

Wireshark: Monitor TLS traffic and debug packet-level behavior.
Debug Logs: Add detailed logs in your implementation to trace state transitions, retries, and errors.
Network Simulators: Use tools like tc (Linux) or a proxy like mitmproxy to simulate 
latency, packet loss, and disconnections.
Servers

Normal Server: Implements the correct protocol and responds as expected.
Faulty Server: Deliberately misbehaves to test the client's robustness. Examples:
Delays responses.
Sends incorrect or malformed messages.
Disconnects unexpectedly.
2. Testing Scenarios
Basic Functional Test

Start a correctly implemented server.
Run the client.
Verify:
The handshake completes successfully.
The CERT_REQ is sent and acknowledged.
The CERT_RESP is received and saved correctly.
The ACK is sent.
Logs and Wireshark show the correct sequence of messages.
Timeout Tests

Simulate Delayed Responses:
Introduce artificial delays in the server's responses (e.g., delay sending CERT_RESP for 4 seconds when the client expects a timeout of 3 seconds).
Verify:
The client retries appropriately.
After the retry limit is reached, the client cleans up and terminates gracefully.
Example server delay:

sleep(4); // Delay before sending CERT_RESP
Long Latency Network:
Simulate a network with high latency using tc (Linux):
sudo tc qdisc add dev eth0 root netem delay 500ms
Verify:
The client handles delays within the timeout threshold.
Logs indicate proper state transitions.
Short Timeout Configuration:
Set timeouts to very small values (e.g., 100ms).
Verify:
The client times out and retries appropriately.
Retry Tests

Server Fails Once:
Simulate a server that fails during the first handshake or protocol step but succeeds on the second attempt.
Verify:
The client retries and successfully completes the protocol.
Logs show the retry mechanism in action.
Exceed Retry Limit:
Simulate a server that always fails (e.g., disconnects immediately).
Verify:
The client retries up to the limit and then terminates with a clear error message.
All resources are cleaned up (e.g., no memory leaks or dangling sockets).
Malformed Message Tests

Wrong Message Type:
Make the server send an incorrect message type (e.g., CERT_RESP header with an invalid type field).
Verify:
The client logs an error but does not crash.
The client retries or terminates as expected.
Incorrect Payload Size:
Send a CERT_RESP header with a payload size larger than the actual data.
Verify:
The client detects the inconsistency and handles it gracefully.
Extra Data:
Append extra bytes after CERT_RESP.
Verify:
The client discards the extra data and does not misinterpret it.
Network Disconnection Tests

Server Disconnects During Handshake:
Simulate the server disconnecting in the middle of the handshake.
Verify:
The client detects the disconnection, retries, and cleans up properly.
Server Disconnects Mid-Protocol:
Simulate the server disconnecting after sending CERT_RESP.
Verify:
The client logs the disconnection and retries appropriately.
Simulating Failures

Faulty Server
Modify the server implementation to inject faults, such as:
Delaying responses.
Sending incorrect or extra data.
Disconnecting at random points.
Network Simulator
Use tc to simulate various network conditions:
Packet Loss:
sudo tc qdisc add dev eth0 root netem loss 10%
High Latency:
sudo tc qdisc add dev eth0 root netem delay 300ms
Bandwidth Limit:
sudo tc qdisc add dev eth0 root tbf rate 1mbit burst 32kbit latency 400ms
3. Monitoring and Debugging
Debug Logs

Ensure detailed logs are enabled in your implementation:

State transitions (e.g., WAIT_FOR_CERT_RESP → SEND_ACK).
Errors (e.g., TLS handshake failed: -0x1234).
Data received and processed:
printf("Buffer content: ");
for (size_t i = 0; i < bytes_received; i++) {
    printf("%02x ", protocol->buffer[i]);
}
printf("\n");
Wireshark

Filter traffic by port or IP to focus on the TLS connection:
tcp.port == 4433
Look for:
Complete and correctly ordered TLS records.
TCP retransmissions (indicating packet loss or delays).
Proper acknowledgments for every TLS record.
4. Success Criteria
Functionality

The client completes the protocol successfully under normal conditions.
Robustness

The client gracefully handles:
Timeouts.
Network issues.
Protocol errors (e.g., malformed messages).
Efficiency

No resource leaks:
Use tools like valgrind to check for memory leaks.
Ensure sockets are closed properly.
5. Automation
Automate your tests using a script:

Start the server with different configurations (e.g., normal, delayed, faulty).
Run the client and capture logs.
Use tools like curl or nc to verify server behavior alongside the client.
Example script:

#!/bin/bash

# Start normal server
./server &
SERVER_PID=$!
sleep 1

# Run client
./client > client_log.txt

# Kill server
kill $SERVER_PID

# Check logs
grep "Protocol completed successfully" client_log.txt
Would you like me to assist in setting up a specific test case or analyzing Wireshark captures?
