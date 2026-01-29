import socket
import json

def try_connect(port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect(('127.0.0.1', port))
        
        # Send get_status command
        req = json.dumps({'command': 'get_status', 'params': {}}).encode('utf-8')
        s.sendall(len(req).to_bytes(4, 'big') + req)
        
        len_bytes = s.recv(4)
        if len_bytes:
            resp_len = int.from_bytes(len_bytes, 'big')
            data = b''
            while len(data) < resp_len:
                chunk = s.recv(min(resp_len - len(data), 4096))
                if not chunk:
                    break
                data += chunk
            result = json.loads(data.decode('utf-8'))
            binary_name = result.get('data', {}).get('binary_name', 'unknown')
            print(f"Port {port}: Connected! Binary = {binary_name}")
            s.close()
            return True, binary_name
        s.close()
        return False, None
    except Exception as e:
        print(f"Port {port}: {type(e).__name__} - {e}")
        return False, None

# Try common ports
for port in [4455, 4456, 18811, 18812, 18813]:
    success, name = try_connect(port)
    if success:
        print(f"  >> Found IDA server on port {port} with {name}")
