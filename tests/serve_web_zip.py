# Mimics the README nginx config: static try_files $uri $uri.html /index.html + /api reverse proxy to backend :8001
import http.server, os, sys, urllib.request, socketserver

ROOT = sys.argv[1]
PORT = int(sys.argv[2])
UPSTREAM = "http://127.0.0.1:8001"


class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=ROOT, **kw)

    def _proxy(self):
        body = None
        if self.headers.get("Content-Length"):
            body = self.rfile.read(int(self.headers["Content-Length"]))
        req = urllib.request.Request(UPSTREAM + self.path, data=body, method=self.command)
        for k, v in self.headers.items():
            if k.lower() not in ("host", "content-length"):
                req.add_header(k, v)
        try:
            r = urllib.request.urlopen(req, timeout=60)
            code, hdrs, data = r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            code, hdrs, data = e.code, e.headers, e.read()
        self.send_response(code)
        for k, v in hdrs.items():
            if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith("/api/"):
            return self._proxy()
        p = self.path.split("?")[0]
        fs = os.path.join(ROOT, p.lstrip("/"))
        if not os.path.isfile(fs):
            if os.path.isfile(fs + ".html"):
                self.path = p + ".html"
            elif not os.path.isdir(fs):
                self.path = "/index.html"
        return super().do_GET()

    def do_POST(self):
        return self._proxy()

    def do_PUT(self):
        return self._proxy()

    def do_DELETE(self):
        return self._proxy()


socketserver.ThreadingTCPServer.allow_reuse_address = True
with socketserver.ThreadingTCPServer(("0.0.0.0", PORT), H) as s:
    s.serve_forever()
