#!/usr/bin/env python3
"""Simple local transport test - single process, no threading."""
import hashlib
import json
import os
import socket
import tempfile
import time
from pathlib import Path

KIND_CONTROL = 0
KIND_DATA = 1
MAX_PAYLOAD = 1024 * 1024

def recv_exact(sock, n):
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return data

def test_local_transport():
    print("=== Local Transport Test ===\n")
    
    # Create server socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', 0))
    port = server.getsockname()[1]
    server.listen(1)
    print(f"Server listening on port {port}")
    
    # Connect client
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', port))
    print("Client connected")
    
    conn, addr = server.accept()
    print(f"Server accepted from {addr}")
    
    # Create test files
    test_dir = Path(tempfile.mkdtemp())
    files = []
    for i in range(5):
        size = 1024 * (i + 1) * 100  # 100KB to 500KB
        data = os.urandom(size)
        path = test_dir / f"test_{i}.bin"
        path.write_bytes(data)
        files.append((path, data))
    
    # Send files
    start_time = time.time()
    for path, data in files:
        # Send file offer
        offer = json.dumps({"type": "file-offer", "name": path.name, "size": len(data)}).encode()
        hdr = bytes([KIND_CONTROL]) + len(offer).to_bytes(4, 'big')
        client.sendall(hdr + offer)
        
        # Send file data in chunks
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + MAX_PAYLOAD]
            hdr = bytes([KIND_DATA]) + (len(chunk) + 4).to_bytes(4, 'big')
            sid_bytes = (0).to_bytes(4, 'big')
            client.sendall(hdr + sid_bytes + chunk)
            offset += len(chunk)
        
        print(f"Sent {path.name} ({len(data)} bytes)")
    
    # Send done signal
    done = json.dumps({"type": "done"}).encode()
    hdr = bytes([KIND_CONTROL]) + len(done).to_bytes(4, 'big')
    client.sendall(hdr + done)
    
    # Receive and verify
    files_received = {}
    while True:
        try:
            hdr = recv_exact(conn, 5)
            kind = hdr[0]
            length = int.from_bytes(hdr[1:5], 'big')
            payload = recv_exact(conn, length)
            
            if kind == KIND_CONTROL:
                msg = json.loads(payload)
                if msg.get("type") == "done":
                    break
                elif msg.get("type") == "file-offer":
                    name = msg.get("name", "unknown")
                    files_received[name] = b''
            elif kind == KIND_DATA:
                sid = int.from_bytes(payload[:4], 'big')
                data = payload[4:]
                if files_received:
                    last_name = list(files_received.keys())[-1]
                    files_received[last_name] += data
        except ConnectionError:
            break
    
    elapsed = time.time() - start_time
    total_size = sum(len(d) for _, d in files)
    
    # Verify integrity
    print(f"\nResults:")
    print(f"  Files sent: {len(files)}")
    print(f"  Files received: {len(files_received)}")
    print(f"  Total size: {total_size} bytes ({total_size/1024:.1f} KB)")
    print(f"  Time: {elapsed:.3f}s")
    print(f"  Speed: {total_size/elapsed/1024/1024:.1f} MB/s")
    
    # Verify hashes
    all_match = True
    for path, data in files:
        sent_hash = hashlib.sha256(data).hexdigest()
        recv_hash = hashlib.sha256(files_received.get(path.name, b'')).hexdigest()
        match = "✓" if sent_hash == recv_hash else "✗"
        if sent_hash != recv_hash:
            all_match = False
        print(f"  {match} {path.name}: sent={sent_hash[:16]} recv={recv_hash[:16]}")
    
    print(f"\nIntegrity: {'PASS' if all_match else 'FAIL'}")
    
    client.close()
    conn.close()
    server.close()
    
    return all_match

if __name__ == "__main__":
    success = test_local_transport()
    exit(0 if success else 1)
