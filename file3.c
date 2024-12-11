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