import json
import os
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


SERVICE = os.getenv("HONEYPOT_SERVICE", "digital_twin")
CERT_DIR = Path("/var/lib/honeypot")
CERT_PATH = CERT_DIR / "server.crt"
KEY_PATH = CERT_DIR / "server.key"


def _ensure_tls_material() -> None:
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    CERT_DIR.chmod(0o700)

    if not CERT_PATH.exists() or not KEY_PATH.exists():
        os.system(
            "openssl req -x509 -newkey rsa:2048 -keyout "
            f"{KEY_PATH} -out {CERT_PATH} -days 365 -nodes -subj '/CN=localhost' >/dev/null 2>&1"
        )

    KEY_PATH.chmod(0o600)
    CERT_PATH.chmod(0o640)


class HoneypotHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        payload = {
            "service": SERVICE,
            "status": "SIMULATED",
            "message": "Interaction recorded in isolated honeypot container",
        }
        encoded = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format, *args):
        return


_ensure_tls_material()
server = HTTPServer(("0.0.0.0", 8080), HoneypotHandler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.maximum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain(str(CERT_PATH), str(KEY_PATH))
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()