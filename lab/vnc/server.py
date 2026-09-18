import socket

def run_vnc_mock():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', 5900))
    s.listen(5)
    print("[+] VNC mock listening on 0.0.0.0:5900", flush=True)

    while True:
        try:
            conn, addr = s.accept()
            # 1. Server sends RFB version banner
            conn.sendall(b'RFB 003.008\n')
            # 2. Client echoes RFB version
            client_ver = conn.recv(12)
            if client_ver.startswith(b'RFB'):
                # 3. Server sends 1 security type: 0x01 (None - no authentication)
                conn.sendall(b'\x01\x01')
                # 4. Client selects security type None (1)
                sel = conn.recv(1)
                if sel == b'\x01':
                    # 5. Server sends 4-byte SecurityResult OK (0x00000000)
                    conn.sendall(b'\x00\x00\x00\x00')
            conn.close()
        except Exception as e:
            print(f"Error: {e}", flush=True)

if __name__ == '__main__':
    run_vnc_mock()
