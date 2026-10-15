"""Bounded length-prefixed JSON framing shared by the IDA client and server."""
import json
import time

MAX_FRAME_BYTES = 32 * 1024 * 1024


def recv_exact(sock, size, timeout=120):
    deadline = time.monotonic() + timeout
    data = bytearray()
    previous_timeout = sock.gettimeout()
    try:
        while len(data) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("IDA frame deadline exceeded")
            sock.settimeout(remaining)
            packet = sock.recv(min(size - len(data), 65536))
            if not packet:
                raise ConnectionError("IDA connection closed during frame")
            data.extend(packet)
    finally:
        sock.settimeout(previous_timeout)
    return bytes(data)


def receive_json(sock, timeout=120, max_bytes=MAX_FRAME_BYTES):
    deadline = time.monotonic() + timeout
    length = int.from_bytes(recv_exact(sock, 4, timeout), "big")
    if not 0 < length <= max_bytes:
        raise ValueError(f"Invalid IDA frame length: {length}")
    remaining = max(0.001, deadline - time.monotonic())
    return json.loads(recv_exact(sock, length, remaining).decode("utf-8"))


def send_json(sock, value, max_bytes=MAX_FRAME_BYTES):
    data = json.dumps(value, ensure_ascii=False).encode("utf-8")
    if not 0 < len(data) <= max_bytes:
        raise ValueError(f"IDA frame exceeds {max_bytes} bytes")
    sock.sendall(len(data).to_bytes(4, "big") + data)
