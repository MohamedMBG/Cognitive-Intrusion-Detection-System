#!/bin/bash
# Run local attack simulation test

echo "=========================================="
echo "ML-IDS Local Attack Simulation Test"
echo "=========================================="
echo ""

# Check if server is already running
if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo "✓ Server already running"
else
    echo "Starting local test server..."
    cd /home/ecerocg/ML-IDS
    python3 tests/local_test_server.py &
    SERVER_PID=$!
    echo "Server PID: $SERVER_PID"
    
    # Wait for server to start
    echo "Waiting for server to initialize..."
    for i in {1..10}; do
        if curl -s http://localhost:8000/health > /dev/null 2>&1; then
            echo "✓ Server ready"
            break
        fi
        sleep 1
    done
fi

echo ""
echo "Running attack simulation..."
echo ""

cd /home/ecerocg/ML-IDS
python3 tests/simulate_attacks.py "$@"

echo ""
echo "=========================================="
echo "Test complete!"
echo "=========================================="

# Optionally stop server
if [ ! -z "$SERVER_PID" ]; then
    echo ""
    read -p "Stop server? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        kill $SERVER_PID 2>/dev/null
        echo "Server stopped"
    else
        echo "Server still running (PID: $SERVER_PID)"
        echo "To stop: kill $SERVER_PID"
    fi
fi
