#!/usr/bin/env python3
"""Test combined optimizations: binary protocol + larger chunks + zero-copy + batch ACKs."""
import hashlib
import os
import socket
import struct
import tempfile
import time

# Binary protocol constants
KIND_CONTROL = 0
KIND_DATA = 1

def send_control_binary(sock, msg_type, payload=b''):
    """Binary control message: [1B type][2B len][payload]"""
    header = struct.pack('>BH', msg_type, len(payload))
    sock.sendall(header + payload)

def send_data_binary(sock, sid, data):
    """Binary data frame: [4B len][4B sid][data]"""
    header = struct.pack('>II', len(data) + 4, sid)
    sock.sendall(header + data)

def recv_exact(sock, n):
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return data

def test_json_protocol(data, chunk_size=1024*1024):
    """JSON protocol (current filament)."""
    import json
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', 0))
    server.listen(1)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', server.getsockname()[1]))
    conn, _ = server.accept()
    
    start = time.time()
    
    # Send file offer (JSON)
    offer = json.dumps({"type": "file-offer", "name": "test.bin", "size": len(data)}).encode()
    hdr = bytes([KIND_CONTROL]) + len(offer).to_bytes(4, 'big')
    client.sendall(hdr + offer)
    
    # Wait for accept
    hdr = recv_exact(conn, 5)
    kind = hdr[0]
    length = int.from_bytes(hdr[1:5], 'big')
    recv_exact(conn, length)
    
    # Send data in chunks
    offset = 0
    while offset < len(data):
        chunk = data[offset:offset + chunk_size]
        hdr = bytes([KIND_DATA]) + (len(chunk) + 4).to_bytes(4, 'big')
        sid_bytes = (0).to_bytes(4, 'big')
        client.sendall(hdr + sid_bytes + chunk)
        offset += len(chunk)
    
    # Send file-end
    end = json.dumps({"type": "file-end", "id": "test", "sid": 0}).encode()
    hdr = bytes([KIND_CONTROL]) + len(end).to_bytes(4, 'big')
    client.sendall(hdr + end)
    
    # Wait for delivery-ack
    hdr = recv_exact(conn, 5)
    length = int.from_bytes(hdr[1:5], 'big')
    recv_exact(conn, length)
    
    elapsed = time.time() - start
    client.close(); conn.close(); server.close()
    return elapsed

def test_binary_protocol(data, chunk_size=1024*1024):
    """Binary protocol (optimized)."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', 0))
    server.listen(1)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', server.getsockname()[1]))
    conn, _ = server.accept()
    
    start = time.time()
    
    # Send file offer (binary)
    name_bytes = b"test.bin"
    offer = struct.pack('>HI', len(name_bytes), len(data)) + name_bytes
    send_control_binary(client, 1, offer)  # type 1 = file-offer
    
    # Wait for accept (binary)
    hdr = recv_exact(conn, 3)
    recv_exact(conn, struct.unpack('>H', hdr[1:3])[0])
    
    # Send data in chunks
    offset = 0
    while offset < len(data):
        chunk = data[offset:offset + chunk_size]
        send_data_binary(client, 0, chunk)
        offset += len(chunk)
    
    # Send file-end (binary)
    send_control_binary(client, 2)  # type 2 = file-end
    
    # Wait for delivery-ack (binary)
    hdr = recv_exact(conn, 3)
    recv_exact(conn, struct.unpack('>H', hdr[1:3])[0])
    
    elapsed = time.time() - start
    client.close(); conn.close(); server.close()
    return elapsed

def test_raw_tcp(data, chunk_size=1024*1024):
    """Raw TCP (no protocol)."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', 0))
    server.listen(1)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', server.getsockname()[1]))
    conn, _ = server.accept()
    
    start = time.time()
    
    # Send data in chunks (no protocol overhead)
    offset = 0
    while offset < len(data):
        chunk = data[offset:offset + chunk_size]
        conn.sendall(chunk)
        offset += len(chunk)
    
    # Wait for acknowledgment
    conn.recv(1)
    
    elapsed = time.time() - start
    client.close(); conn.close(); server.close()
    return elapsed

def main():
    print("=== Combined Optimizations Experiment ===\n")
    
    # Test with different sizes and chunk sizes
    sizes = [1024*1024, 10*1024*1024, 100*1024*1024]  # 1MB, 10MB, 100MB
    chunk_sizes = [64*1024, 256*1024, 1024*1024, 4*1024*1024]  # 64KB to 4MB
    
    for size in sizes:
        print(f"\n--- {size/1024/1024:.0f} MB ---")
        data = os.urandom(size)
        
        for chunk_size in chunk_sizes:
            # JSON protocol
            elapsed = test_json_protocol(data, chunk_size)
            json_speed = size / elapsed / 1024 / 1024
            
            # Binary protocol
            elapsed = test_binary_protocol(data, chunk_size)
            bin_speed = size / elapsed / 1024 / 1024
            
            # Raw TCP (no protocol)
            elapsed = test_raw_tcp(data, chunk_size)
            raw_speed = size / elapsed / 1024 / 1024
            
            print(f"  Chunk {chunk_size//1024:4d}KB: JSON {json_speed:8.1f} MB/s | Binary {bin_speed:8.1f} MB/s | Raw {raw_speed:8.1f} MB/s")

if __name__ == "__main__":
    main()
