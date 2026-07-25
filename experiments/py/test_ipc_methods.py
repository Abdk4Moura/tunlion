#!/usr/bin/env python3
"""Test different IPC methods for same-machine transfer.

Compares:
1. TCP localhost (baseline)
2. Unix domain sockets
3. Shared memory (mmap)
4. Pipe (os.pipe)
"""
import hashlib
import mmap
import os
import socket
import tempfile
import time

def test_tcp_localhost(data, port=0):
    """TCP localhost transfer."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', port))
    server.listen(1)
    
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', server.getsockname()[1]))
    conn, _ = server.accept()
    
    start = time.time()
    offset = 0
    while offset < len(data):
        chunk = data[offset:offset + 1024*1024]
        conn.sendall(chunk)
        offset += len(chunk)
    
    # Read acknowledgment
    conn.recv(1)
    elapsed = time.time() - start
    
    client.close()
    conn.close()
    server.close()
    
    return elapsed


def test_unix_socket(data):
    """Unix domain socket transfer."""
    sock_path = tempfile.mktemp()
    
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    server.listen(1)
    
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(sock_path)
    conn, _ = server.accept()
    
    start = time.time()
    offset = 0
    while offset < len(data):
        chunk = data[offset:offset + 1024*1024]
        conn.sendall(chunk)
        offset += len(chunk)
    
    # Read acknowledgment
    conn.recv(1)
    elapsed = time.time() - start
    
    client.close()
    conn.close()
    server.close()
    os.unlink(sock_path)
    
    return elapsed


def test_shared_memory(data):
    """Shared memory (mmap) transfer with signal."""
    shm_path = tempfile.mktemp()
    
    # Create shared memory file
    with open(shm_path, 'wb') as f:
        f.write(b'\0' * len(data))
    
    # Write data to shared memory
    with open(shm_path, 'r+b') as f:
        mm = mmap.mmap(f.fileno(), len(data))
        start = time.time()
        mm.write(data)
        mm.flush()
        elapsed_write = time.time() - start
        mm.close()
    
    # Read data from shared memory
    with open(shm_path, 'rb') as f:
        mm = mmap.mmap(f.fileno(), len(data))
        start = time.time()
        read_data = mm.read(len(data))
        mm.close()
        elapsed_read = time.time() - start
    
    os.unlink(shm_path)
    
    return elapsed_write + elapsed_read


def test_pipe(data):
    """Pipe transfer."""
    read_fd, write_fd = os.pipe()
    
    start = time.time()
    offset = 0
    while offset < len(data):
        chunk = data[offset:offset + 1024*1024]
        os.write(write_fd, chunk)
        offset += len(chunk)
    os.close(write_fd)
    
    # Read all data
    read_data = b''
    while True:
        chunk = os.read(read_fd, 1024*1024)
        if not chunk:
            break
        read_data += chunk
    os.close(read_fd)
    elapsed = time.time() - start
    
    return elapsed


def main():
    print("=== IPC Methods Comparison ===\n")
    
    # Test with different sizes
    sizes = [1024*1024, 10*1024*1024, 100*1024*1024]  # 1MB, 10MB, 100MB
    
    for size in sizes:
        print(f"\n--- {size/1024/1024:.0f} MB ---")
        data = os.urandom(size)
        
        # TCP
        elapsed = test_tcp_localhost(data)
        speed = size / elapsed / 1024 / 1024
        print(f"  TCP localhost:     {speed:8.1f} MB/s ({elapsed:.3f}s)")
        
        # Unix socket
        elapsed = test_unix_socket(data)
        speed = size / elapsed / 1024 / 1024
        print(f"  Unix socket:      {speed:8.1f} MB/s ({elapsed:.3f}s)")
        
        # Shared memory
        elapsed = test_shared_memory(data)
        speed = size / elapsed / 1024 / 1024
        print(f"  Shared memory:    {speed:8.1f} MB/s ({elapsed:.3f}s)")
        
        # Pipe
        elapsed = test_pipe(data)
        speed = size / elapsed / 1024 / 1024
        print(f"  Pipe:             {speed:8.1f} MB/s ({elapsed:.3f}s)")


if __name__ == "__main__":
    main()
