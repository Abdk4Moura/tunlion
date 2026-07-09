#!/usr/bin/env python3
"""Test local transport for same-machine peers.

This script tests TCP localhost transport between two Python peers,
demonstrating the protocol before implementing in Rust.

Usage:
  # Terminal 1: Start receiver
  python experiments/py/test_local_transport.py receiver

  # Terminal 2: Start sender (after receiver is ready)
  python experiments/py/test_local_transport.py sender

  # Or run both in one terminal (background receiver):
  python experiments/py/test_local_transport.py test
"""
import hashlib
import json
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))
from filament_lab.signaling import Signaling
from filament_lab.peer import Peer
from filament_lab.crypto import fresh_secret, channel_of


# Protocol constants (matching Rust implementation)
KIND_CONTROL = 0
KIND_DATA = 1
MAX_PAYLOAD = 1024 * 1024  # 1 MiB


class LocalTransport:
    """TCP localhost transport for same-machine peers."""
    
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.dead = False
    
    def send_control(self, msg: dict) -> None:
        payload = json.dumps(msg).encode()
        hdr = bytes([KIND_CONTROL]) + len(payload).to_bytes(4, 'big')
        self.sock.sendall(hdr + payload)
    
    def send_frame(self, sid: int, data: bytes) -> None:
        hdr = bytes([KIND_DATA]) + (len(data) + 4).to_bytes(4, 'big')
        sid_bytes = sid.to_bytes(4, 'big')
        self.sock.sendall(hdr + sid_bytes + data)
    
    def recv(self) -> tuple[int, bytes]:
        """Receive a message, returns (kind, payload)."""
        hdr = self._recv_exact(5)
        kind = hdr[0]
        length = int.from_bytes(hdr[1:5], 'big')
        payload = self._recv_exact(length)
        return kind, payload
    
    def recv_frame(self) -> tuple[int, bytes]:
        """Receive a data frame, returns (sid, data)."""
        kind, payload = self.recv()
        if kind != KIND_DATA:
            raise ValueError(f"Expected KIND_DATA, got {kind}")
        sid = int.from_bytes(payload[:4], 'big')
        data = payload[4:]
        return sid, data
    
    def _recv_exact(self, n: int) -> bytes:
        data = b''
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                self.dead = True
                raise ConnectionError("Connection closed")
            data += chunk
        return data


def start_receiver(port: int = 0) -> int:
    """Start a TCP receiver that accepts a connection and receives files.
    Returns the actual port if port was 0."""
    print(f"Receiver starting on port {port}...")
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', port))
    actual_port = server.getsockname()[1]
    server.listen(1)
    
    print(f"Listening on port {actual_port}")
    conn, addr = server.accept()
    print(f"Connected from {addr}")
    
    transport = LocalTransport(conn)
    
    # Receive files until control message says done
    files_received = {}
    while True:
        try:
            kind, payload = transport.recv()
            
            if kind == KIND_CONTROL:
                msg = json.loads(payload)
                if msg.get("type") == "done":
                    print(f"\nTransfer complete! Received {len(files_received)} file(s)")
                    for name, data in files_received.items():
                        print(f"  {name}: {len(data)} bytes, sha256={hashlib.sha256(data).hexdigest()[:16]}...")
                    break
                elif msg.get("type") == "file-offer":
                    name = msg.get("name", "unknown")
                    size = msg.get("size", 0)
                    print(f"Receiving {name} ({size} bytes)...")
                    files_received[name] = b''
            elif kind == KIND_DATA:
                sid, data = transport.recv_frame()
                # Simple: append to last file
                if files_received:
                    last_name = list(files_received.keys())[-1]
                    files_received[last_name] += data
        except ConnectionError:
            print("Connection closed")
            break
    
    server.close()


def start_sender(port: int = 9999) -> None:
    """Start a TCP sender that connects and sends files."""
    print(f"Sender connecting to port {port}...")
    
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect(('127.0.0.1', port))
    print("Connected!")
    
    transport = LocalTransport(conn)
    
    # Create test files
    test_dir = Path(tempfile.mkdtemp())
    files = []
    for i in range(5):
        size = 1024 * (i + 1)  # 1KB to 5KB
        data = os.urandom(size)
        path = test_dir / f"test_{i}.bin"
        path.write_bytes(data)
        files.append((path, data))
        print(f"Created {path.name} ({size} bytes)")
    
    # Send files
    start_time = time.time()
    for path, data in files:
        # Send file offer
        transport.send_control({
            "type": "file-offer",
            "name": path.name,
            "size": len(data),
        })
        
        # Send file data in chunks
        chunk_size = MAX_PAYLOAD
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + chunk_size]
            transport.send_frame(0, chunk)
            offset += chunk_size
        
        print(f"Sent {path.name} ({len(data)} bytes)")
    
    # Send done signal
    transport.send_control({"type": "done"})
    
    elapsed = time.time() - start_time
    total_size = sum(len(d) for _, d in files)
    print(f"\nTransfer complete: {total_size} bytes in {elapsed:.3f}s ({total_size/elapsed/1024/1024:.1f} MB/s)")
    
    conn.close()


def run_test() -> None:
    """Run a self-contained test with background receiver."""
    print("=== Local Transport Test ===\n")
    
    # Use port 0 to get a random available port
    port = 0
    
    # Start receiver in background
    actual_port = [0]
    def receiver_wrapper():
        actual_port[0] = start_receiver(port)
    
    receiver_thread = threading.Thread(target=receiver_wrapper, daemon=True)
    receiver_thread.start()
    time.sleep(1)  # Wait for receiver to start and be ready
    
    # Run sender on the actual port
    start_sender(actual_port[0])
    
    # Wait for receiver to finish
    receiver_thread.join(timeout=5)
    print("\nTest complete!")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_local_transport.py [receiver|sender|test]")
        sys.exit(1)
    
    mode = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9999
    
    if mode == "receiver":
        start_receiver(port)
    elif mode == "sender":
        start_sender(port)
    elif mode == "test":
        run_test()
    else:
        print(f"Unknown mode: {mode}")
        sys.exit(1)
