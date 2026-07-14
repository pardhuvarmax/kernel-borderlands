#!/usr/bin/env python3
import socket
import time
import os

print(f"Starting connection flood from PID: {os.getpid()}")
count = 0

# The rate limiter allows 100 per sec. We will flood ~5000 in less than a second.
while count < 5000:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 127.0.0.1 is standard, trying to connect to closed port
        s.connect(('127.0.0.1', 59999))
    except ConnectionRefusedError:
        pass
    finally:
        s.close()
    count += 1

print(f"Flooded {count} connection attempts.")
# Sleep to allow the token bucket to refill and flush the batched drop message
time.sleep(1)
print("Finished.")
