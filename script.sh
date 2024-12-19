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


#!/bin/bash

# Configuration
SERVER_CMD="./server"
CLIENT_CMD="./client"
ITERATIONS=1000
LOG_FILE="protocol_test.log"

# Clear previous log file
> $LOG_FILE

echo "Starting protocol test for $ITERATIONS iterations..." | tee -a $LOG_FILE

# Function to start the server
start_server() {
    $SERVER_CMD > server_output.log 2>&1 &
    SERVER_PID=$!
    sleep 1 # Give the server time to start
}

# Function to stop the server
stop_server() {
    kill $SERVER_PID 2>/dev/null
    wait $SERVER_PID 2>/dev/null
}

# Run tests
success_count=0
failure_count=0

for ((i=1; i<=ITERATIONS; i++)); do
    echo "Iteration $i" | tee -a $LOG_FILE
    
    # Generate a random seed
    SEED=$RANDOM
    echo "Using seed: $SEED" | tee -a $LOG_FILE

    # Start the server
    start_server

    # Run the client
    $CLIENT_CMD --seed $SEED > client_output.log 2>&1
    CLIENT_EXIT_CODE=$?

    # Stop the server
    stop_server

    # Check result
    if [ $CLIENT_EXIT_CODE -eq 0 ]; then
        echo "Iteration $i: SUCCESS" | tee -a $LOG_FILE
        success_count=$((success_count + 1))
    else
        echo "Iteration $i: FAILURE" | tee -a $LOG_FILE
        failure_count=$((failure_count + 1))
        # Save logs for debugging
        cp server_output.log server_output_$i.log
        cp client_output.log client_output_$i.log
    fi
done

# Summary
echo "Test completed: $success_count successes, $failure_count failures." | tee -a $LOG_FILE

# Exit with failure if any tests failed
if [ $failure_count -gt 0 ]; then
    exit 1
else
    exit 0
fi

#Changes Made
#Removed Host and Port Arguments:
#The script assumes the server listens on the pre-configured port and address (localhost).
#Kept Random Seed:
#The random seed is still generated for each iteration to introduce variability.
#The seed is passed as a --seed argument to the client only.
#Logs:
#Server and client logs are saved separately to ensure debuggability.
#How to Use
#Save the script as run_protocol_tests.sh.
#Make it executable:
#chmod +x run_protocol_tests.sh
#Run the script:
#./run_protocol_tests.sh
#Expected Output
#Success Logs: Each successful iteration will log Iteration X: SUCCESS.
#Failure Logs: Failures will save the server and client logs with iteration-specific filenames (server_output_<iteration>.log, client_output_<iteration>.log).
#Customizations
#Fixed Seeds: If you want reproducible results with fixed seeds, replace the random seed generation with a predefined list:
#for SEED in 123 456 789; do
#    ...
#done
#Parallel Execution: If the protocol supports parallel testing, run multiple instances concurrently using background processes or GNU parallel.
#Would you like help expanding this script further or debugging issues found during testing?