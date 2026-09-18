import socket
import sys

def run_jdwp_mock():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', 8000))
    s.listen(5)
    print("[+] JDWP mock listening on 0.0.0.0:8000", flush=True)

    while True:
        try:
            conn, addr = s.accept()
            data = conn.recv(14)
            if data == b'JDWP-Handshake':
                conn.sendall(b'JDWP-Handshake')
            conn.close()
        except Exception as e:
            print(f"Error: {e}", flush=True)

if __name__ == '__main__':
    run_jdwp_mock()
