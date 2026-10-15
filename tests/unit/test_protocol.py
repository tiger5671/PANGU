import json
import socket
import pytest
from core.bridge.protocol import receive_json, send_json, MAX_FRAME_BYTES
from core.bridge.ida_client import IDAProClient


class FragmentedSocket:
    def __init__(self, data=b"", chunk=1):
        self.data, self.chunk, self.timeout = data, chunk, 7
        self.sent, self.closed = b"", False
    def gettimeout(self): return self.timeout
    def settimeout(self, value): self.timeout = value
    def recv(self, size):
        count = min(size, self.chunk)
        data, self.data = self.data[:count], self.data[count:]
        return data
    def sendall(self, data): self.sent += data
    def close(self): self.closed = True


def frame(value):
    data = json.dumps(value).encode()
    return len(data).to_bytes(4, "big") + data


def test_fragmented_header_body_and_unicode_round_trip():
    receiver = FragmentedSocket(frame({"status": "ok", "data": "固件"}))
    assert receive_json(receiver) == {"status": "ok", "data": "固件"}
    assert receiver.timeout == 7
    sender = FragmentedSocket()
    send_json(sender, {"data": "固件"})
    assert receive_json(FragmentedSocket(sender.sent)) == {"data": "固件"}


@pytest.mark.parametrize("data", [b"\0\0", (MAX_FRAME_BYTES + 1).to_bytes(4, "big"),
                                  b"\0\0\0\0", b"\0\0\0\x03{"])
def test_incomplete_or_oversized_frames_fail(data):
    with pytest.raises((ValueError, ConnectionError)):
        receive_json(FragmentedSocket(data))


def test_client_discards_broken_connection_without_replay():
    client = IDAProClient()
    transport = FragmentedSocket(b"\0\0")
    client.sock = transport
    assert client.ping()["status"] == "error"
    assert transport.closed and client.sock is None
    assert len(transport.sent) > 0
    assert client.ping()["error"] == "Not connected"


def test_connect_is_idempotent_and_closes_on_error(monkeypatch):
    calls = []
    def connect(*args):
        calls.append(args)
        return FragmentedSocket()
    monkeypatch.setattr(socket, "create_connection", connect)
    client = IDAProClient()
    assert client.connect() and client.connect()
    assert len(calls) == 1
    client.close()
    assert client.sock is None
