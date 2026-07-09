#!/usr/bin/env python3
"""Filament protocol experiments - testing acknowledgment strategies.

Tests the actual filament file-transfer protocol over TCP localhost:
1. Baseline: send chunks, wait for each ACK
2. Burst mode: send multiple chunks before waiting for ACK
3. Pipeline mode: send all chunks without waiting for ACK

Usage:
  python3 experiments/py/test_filament_protocol.py
"""
import hashlib
import json
import os
import socket
import tempfile
import time

# Protocol constants (matching Rust implementation)
KIND_CONTROL = 0
KIND_DATA = 1
MAX_PAYLOAD = 1024 * 1024  # 1 MiB


class FilamentProtocol:
    """Implements the filament file-transfer protocol over TCP."""
    
    def __init__(self, sock: socket.socket):
        self.sock = sock
    
    def send_control(self, msg: dict) -> None:
        payload = json.dumps(msg).encode()
        hdr = bytes([KIND_CONTROL]) + len(payload).to_bytes(4, 'big')
        self.sock.sendall(hdr + payload)
    
    def send_frame(self, sid: int, data: bytes) -> None:
        hdr = bytes([KIND_DATA]) + (len(data) + 4).to_bytes(4, 'big')
        sid_bytes = sid.to_bytes(4, 'big')
        self.sock.sendall(hdr + sid_bytes + data)
    
    def recv(self) -> tuple:
        hdr = self._recv_exact(5)
        kind = hdr[0]
        length = int.from_bytes(hdr[1:5], 'big')
        payload = self._recv_exact(length)
        return kind, payload
    
    def _recv_exact(self, n: int) -> bytes:
        data = b''
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        return data


def sender_baseline(files, port):
    """Baseline: send chunks, wait for each ACK."""
    print("\n=== Baseline: Wait for each ACK ===")
    
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect(('127.0.0.1', port))
    proto = FilamentProtocol(conn)
    
    start = time.time()
    total_bytes = 0
    
    for i, (path, data) in enumerate(files):
        file_id = f"file-{i}"
        sid = i
        
        # Send file offer
        proto.send_control({
            "type": "file-offer",
            "id": file_id,
            "sid": sid,
            "name": path.name,
            "size": len(data),
            "mime": "application/octet-stream",
        })
        
        # Wait for accept
        kind, payload = proto.recv()
        assert kind == KIND_CONTROL
        msg = json.loads(payload)
        assert msg["type"] == "file-accept"
        
        # Send data in chunks, wait for each to be buffered
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + MAX_PAYLOAD]
            proto.send_frame(sid, chunk)
            offset += len(chunk)
            total_bytes += len(chunk)
        
        # Send file-end
        proto.send_control({"type": "file-end", "id": file_id, "sid": sid})
        
        # Wait for delivery-ack
        kind, payload = proto.recv()
        assert kind == KIND_CONTROL
        msg = json.loads(payload)
        assert msg["type"] == "delivery-ack"
    
    # Send done
    proto.send_control({"type": "done"})
    
    elapsed = time.time() - start
    conn.close()
    
    return total_bytes, elapsed


def sender_burst(files, port, burst_size=10):
    """Burst mode: send multiple chunks before waiting for ACK."""
    print(f"\n=== Burst Mode: {burst_size} chunks per ACK ===")
    
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect(('127.0.0.1', port))
    proto = FilamentProtocol(conn)
    
    start = time.time()
    total_bytes = 0
    
    for i, (path, data) in enumerate(files):
        file_id = f"file-{i}"
        sid = i
        
        # Send file offer
        proto.send_control({
            "type": "file-offer",
            "id": file_id,
            "sid": sid,
            "name": path.name,
            "size": len(data),
            "mime": "application/octet-stream",
        })
        
        # Wait for accept
        kind, payload = proto.recv()
        assert kind == KIND_CONTROL
        msg = json.loads(payload)
        assert msg["type"] == "file-accept"
        
        # Send data in bursts
        offset = 0
        while offset < len(data):
            # Send burst_size chunks without waiting
            for _ in range(burst_size):
                if offset >= len(data):
                    break
                chunk = data[offset:offset + MAX_PAYLOAD]
                proto.send_frame(sid, chunk)
                offset += len(chunk)
                total_bytes += len(chunk)
        
        # Send file-end
        proto.send_control({"type": "file-end", "id": file_id, "sid": sid})
        
        # Wait for delivery-ack
        kind, payload = proto.recv()
        assert kind == KIND_CONTROL
        msg = json.loads(payload)
        assert msg["type"] == "delivery-ack"
    
    # Send done
    proto.send_control({"type": "done"})
    
    elapsed = time.time() - start
    conn.close()
    
    return total_bytes, elapsed


def sender_pipeline(files, port):
    """Pipeline mode: send all chunks without waiting for ACK."""
    print("\n=== Pipeline Mode: No ACKs during transfer ===")
    
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect(('127.0.0.1', port))
    proto = FilamentProtocol(conn)
    
    start = time.time()
    total_bytes = 0
    
    for i, (path, data) in enumerate(files):
        file_id = f"file-{i}"
        sid = i
        
        # Send file offer
        proto.send_control({
            "type": "file-offer",
            "id": file_id,
            "sid": sid,
            "name": path.name,
            "size": len(data),
            "mime": "application/octet-stream",
        })
        
        # Wait for accept
        kind, payload = proto.recv()
        assert kind == KIND_CONTROL
        msg = json.loads(payload)
        assert msg["type"] == "file-accept"
        
        # Send ALL data without waiting
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + MAX_PAYLOAD]
            proto.send_frame(sid, chunk)
            offset += len(chunk)
            total_bytes += len(chunk)
        
        # Send file-end
        proto.send_control({"type": "file-end", "id": file_id, "sid": sid})
        
        # Wait for delivery-ack
        kind, payload = proto.recv()
        assert kind == KIND_CONTROL
        msg = json.loads(payload)
        assert msg["type"] == "delivery-ack"
    
    # Send done
    proto.send_control({"type": "done"})
    
    elapsed = time.time() - start
    conn.close()
    
    return total_bytes, elapsed


def receiver(actual_port):
    """Receive files using the filament protocol."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', actual_port[0]))
    actual_port[0] = server.getsockname()[1]
    server.listen(1)
    
    conn, _ = server.accept()
    proto = FilamentProtocol(conn)
    
    files_received = {}
    while True:
        try:
            kind, payload = proto.recv()
            
            if kind == KIND_CONTROL:
                msg = json.loads(payload)
                if msg.get("type") == "done":
                    break
                elif msg.get("type") == "file-offer":
                    file_id = msg["id"]
                    name = msg["name"]
                    size = msg["size"]
                    # Send accept
                    proto.send_control({"type": "file-accept", "id": file_id, "offset": 0})
                    files_received[file_id] = {"name": name, "size": size, "data": b''}
                elif msg.get("type") == "file-end":
                    file_id = msg["id"]
                    # Verify and send delivery-ack
                    if file_id in files_received:
                        file_data = files_received[file_id]["data"]
                        expected_size = files_received[file_id]["size"]
                        if len(file_data) == expected_size:
                            proto.send_control({
                                "type": "delivery-ack",
                                "id": file_id,
                                "sid": msg.get("sid", 0),
                                "v": 1,
                            })
            elif kind == KIND_DATA:
                sid = int.from_bytes(payload[:4], 'big')
                data = payload[4:]
                # Find the file being received
                for file_id, file_info in files_received.items():
                    if len(file_info["data"]) < file_info["size"]:
                        file_info["data"] += data
                        break
        except ConnectionError:
            break
    
    conn.close()
    server.close()
    
    return files_received


def run_experiment(name, sender_func, files, port):
    """Run a sender-receiver experiment."""
    import threading
    
    # Start receiver in background
    result = [None]
    actual_port = [port]
    def receiver_wrapper():
        result[0] = receiver(actual_port)
    
    receiver_thread = threading.Thread(target=receiver_wrapper, daemon=True)
    receiver_thread.start()
    time.sleep(2)  # Wait for receiver to start and be ready
    
    # Run sender
    total_bytes, elapsed = sender_func(files, actual_port[0])
    
    # Wait for receiver
    receiver_thread.join(timeout=5)
    
    speed = total_bytes / elapsed / 1024 / 1024 if elapsed > 0 else 0
    print(f"  Speed: {speed:.1f} MB/s ({total_bytes/1024:.1f} KB in {elapsed:.3f}s)")
    
    return speed


def main():
    print("=== Filament Protocol Experiments ===\n")
    
    # Create test files (unique, different sizes)
    test_dir = tempfile.mkdtemp()
    files = []
    for i in range(10):
        size = 1024 * 100 * (i + 1)  # 100KB to 1MB
        data = os.urandom(size)
        path = os.path.join(test_dir, f"test_{i}.bin")
        with open(path, 'wb') as f:
            f.write(data)
        files.append((type('Path', (), {'name': f'test_{i}.bin'})(), data))
    
    total_size = sum(len(d) for _, d in files)
    print(f"Test files: {len(files)} files, {total_size/1024:.1f} KB total\n")
    
    # Run experiments
    port = 0
    
    speeds = {}
    speeds['baseline'] = run_experiment("Baseline", lambda f, p: sender_baseline(f, p), files, port)
    
    for burst in [5, 10, 20]:
        speeds[f'burst-{burst}'] = run_experiment(
            f"Burst-{burst}",
            lambda f, p, b=burst: sender_burst(f, p, b),
            files, port
        )
    
    speeds['pipeline'] = run_experiment("Pipeline", sender_pipeline, files, port)
    
    # Summary
    print("\n=== Summary ===")
    print(f"{'Mode':<15} {'Speed':>10}")
    print("-" * 27)
    for mode, speed in speeds.items():
        print(f"{mode:<15} {speed:>10.1f} MB/s")
    
    # Cleanup
    import shutil
    shutil.rmtree(test_dir)


if __name__ == "__main__":
    main()
