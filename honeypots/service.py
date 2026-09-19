import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer


SERVICE = os.getenv("HONEYPOT_SERVICE", "digital_twin")


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


HTTPServer(("0.0.0.0", 8080), HoneypotHandler).serve_forever()