#!/usr/bin/env python3
import socket
import time
import os
import threading

print(f"Starting deep resource isolation test from PID: {os.getpid()}")

def flood_port_a():
    # Flood the "smoke grenade" port to exhaust its bucket
    for _ in range(5000):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('127.0.0.1', 59999))
        except ConnectionRefusedError:
            pass
        finally:
            s.close()
    print("Finished smoke grenade flood on port 59999.")

def secret_c2_connection():
    # Wait a tiny bit to ensure the flood has started and exhausted the main bucket
    time.sleep(0.2)
    print("Attempting 'secret' connection to port 60000 (C2 server)...")
    for _ in range(3):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('127.0.0.1', 60000))
        except ConnectionRefusedError:
            pass
        finally:
            s.close()
    print("Finished secret connections.")

t1 = threading.Thread(target=flood_port_a)
t2 = threading.Thread(target=secret_c2_connection)

t1.start()
t2.start()

t1.join()
t2.join()

time.sleep(1) # wait for batch summary flush
print("Test complete.")
