from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import secrets
import socket
import subprocess
import threading
import time
import urllib.parse
import webbrowser
from dataclasses import dataclass
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import paramiko

from tester import test_link

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
XRAY = ROOT / "tools" / "xray" / "xray.exe"
PROJECT_CLIENT = ROOT.name
MAX_BODY = 1_000_000
TLS_PORTS = (443, 8443, 2053, 2096, 8080, 80)
PLAIN_PORTS = (80, 8080, 2053, 2096, 8443, 443)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
SESSIONS: dict[str, "ServerSession"] = {}
LOCK = threading.Lock()


@dataclass
class ServerSession:
    host: str
    port: int
    username: str
    password: str
    fingerprint: str
    api_base: str
    api_token: str
    public_ip: str
    created: float


class FingerprintPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, expected: str):
        self.expected = expected

    def missing_host_key(self, client, hostname, key):
        actual = "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        if actual != self.expected:
            raise paramiko.SSHException("SSH host fingerprint changed")


def probe_fingerprint(host: str, port: int) -> str:
    with socket.create_connection((host, port), timeout=10) as sock:
        transport = paramiko.Transport(sock)
        try:
            transport.start_client(timeout=10)
            key = transport.get_remote_server_key()
            return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        finally:
            transport.close()


def ssh_connect(session: ServerSession) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(FingerprintPolicy(session.fingerprint))
    client.connect(session.host, port=session.port, username=session.username, password=session.password, look_for_keys=False, allow_agent=False, timeout=12)
    return client


def remote(session: ServerSession, script: str, check: bool = True) -> str:
    encoded = base64.b64encode(script.encode()).decode()
    client = ssh_connect(session)
    try:
        _, stdout, stderr = client.exec_command(f"printf %s {encoded} | base64 -d | bash")
        output, error = stdout.read().decode(errors="replace"), stderr.read().decode(errors="replace")
        code = stdout.channel.recv_exit_status()
        if check and code:
            raise RuntimeError((error or output or f"remote exit {code}")[-1000:])
        return output
    finally:
        client.close()


def token_candidates(raw: str) -> list[str]:
    lines = [x.strip() for x in raw.replace("\r", "").splitlines() if x.strip()]
    values = lines + [x.split(":", 1)[-1].strip() for x in lines if ":" in x] + [x.split()[-1] for x in lines]
    return list(dict.fromkeys(x for x in values if len(x) >= 16 and " " not in x))


def remote_curl(session: ServerSession, base: str, token: str, method: str, path: str, body: dict | None = None) -> dict:
    payload = base64.b64encode(json.dumps(body).encode()).decode() if body is not None else ""
    script = f'''set -e
body=$(printf %s '{payload}' | base64 -d)
args=(-ksS --max-time 20 -X '{method}' -H 'Authorization: Bearer {token}' -H 'Content-Type: application/json')
[ -n "$body" ] && args+=(--data-binary "$body")
curl "${{args[@]}}" '{base}{path}'
'''
    result = json.loads(remote(session, script))
    if not result.get("success"):
        raise RuntimeError(result.get("msg") or "3x-ui API rejected request")
    return result


def discover(data: dict) -> tuple[str, dict]:
    host = str(data.get("host", "")).strip()
    port = int(data.get("port", 22))
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    if not host or not username or not password:
        raise ValueError("Host, username, and password are required")
    actual = probe_fingerprint(host, port)
    if data.get("fingerprint") != actual:
        return "trust", {"fingerprint": actual}
    temp = ServerSession(host, port, username, password, actual, "", "", host, time.time())
    show = remote(temp, "/usr/local/x-ui/x-ui setting -show true 2>&1 || true")
    token_raw = remote(temp, "/usr/local/x-ui/x-ui setting -getApiToken true 2>/dev/null || true")
    ports = [int(x) for x in re.findall(r"(?:port|webPort)[^0-9]{0,8}([0-9]{2,5})", show, re.I)]
    listeners = remote(temp, "ss -lntH | awk '{print $4}' | sort -u", check=False).splitlines()
    ports += [int(x.rsplit(":", 1)[1]) for x in listeners if x.rsplit(":", 1)[-1].isdigit()]
    base_path_match = re.search(r"webBasePath[^/\n]*([^\s]+)", show, re.I)
    base_path = (base_path_match.group(1).strip() if base_path_match else "/").strip()
    paths = list(dict.fromkeys([base_path.rstrip("/"), "", "/api"]))
    bases = [f"{scheme}://127.0.0.1:{p}{path}/panel/api" for p in dict.fromkeys(ports + [54321, 8000, 2053]) if 0 < p < 65536 for path in paths for scheme in ("https", "http")]
    chosen = token = ""
    for candidate_token in token_candidates(token_raw):
        for base in bases:
            try:
                if remote_curl(temp, base, candidate_token, "GET", "/inbounds/options").get("success"):
                    chosen, token = base, candidate_token
                    break
            except Exception:
                pass
        if chosen:
            break
    if not chosen:
        raise RuntimeError("3x-ui was found over SSH, but its authenticated panel API could not be detected")
    temp.api_base, temp.api_token = chosen, token
    detected_ip = remote(temp, "curl -4 -sS --max-time 10 https://api.ipify.org || true", check=False).strip()
    try:
        temp.public_ip = str(ipaddress.ip_address(detected_ip))
    except ValueError:
        temp.public_ip = socket.gethostbyname(host)
    version = remote(temp, "/usr/local/x-ui/x-ui version 2>&1 || /usr/local/x-ui/x-ui -v 2>&1 || true", check=False).strip()[-300:]
    xray_version = remote(temp, "/usr/local/x-ui/bin/xray-linux-amd64 version 2>&1 | head -n2 || true", check=False).strip()
    certs = remote(temp, "find /root/cert /etc/letsencrypt/live -maxdepth 3 -type f \\( -name fullchain.pem -o -name cert.pem \\) 2>/dev/null | sort", check=False).splitlines()
    inbounds = remote_curl(temp, chosen, token, "GET", "/inbounds/options")["obj"]
    sid = secrets.token_urlsafe(24)
    with LOCK:
        SESSIONS[sid] = temp
    return "ok", {"session": sid, "fingerprint": actual, "version": version, "xray_version": xray_version, "listeners": listeners, "certificates": certs, "inbounds": inbounds}


def api(session: ServerSession, method: str, path: str, body: dict | None = None) -> dict:
    return remote_curl(session, session.api_base, session.api_token, method, path, body)


def port_in_use(session: ServerSession, port: int) -> bool:
    return remote(session, f"ss -lntH 'sport = :{port}' | head -n1", check=False).strip() != ""


def choose_port(session: ServerSession, template: str, requested: int, configured: set[int]) -> tuple[int, bool]:
    if requested:
        if not 1 <= requested <= 65535:
            raise ValueError("Inbound port must be between 1 and 65535")
        if requested in configured or port_in_use(session, requested):
            raise ValueError(f"Port {requested} is already used on the server")
        return requested, False
    order = TLS_PORTS if ("tls" in template or "reality" in template) else PLAIN_PORTS
    for port in order:
        if port not in configured and not port_in_use(session, port):
            return port, True
    raise RuntimeError("None of the preferred ports are free: " + ", ".join(map(str, order)))


def open_firewall(session: ServerSession, port: int) -> str:
    script = f'''set -e
if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
  if ufw status | grep -Eq '^{port}/tcp[[:space:]]+ALLOW'; then echo ufw-open
  else ufw allow {port}/tcp comment 'inbound-gen' >/dev/null; echo ufw-added; fi
elif command -v firewall-cmd >/dev/null && firewall-cmd --state 2>/dev/null | grep -q running; then
  if firewall-cmd --quiet --query-port={port}/tcp; then echo firewalld-open
  else firewall-cmd --permanent --add-port={port}/tcp >/dev/null; firewall-cmd --reload >/dev/null; echo firewalld-added; fi
else
  echo no-active-firewall
fi'''
    return remote(session, script).strip().splitlines()[-1]


def rollback_firewall(session: ServerSession, port: int, action: str) -> None:
    if action == "ufw-added":
        remote(session, f"ufw --force delete allow {port}/tcp >/dev/null", check=False)
    elif action == "firewalld-added":
        remote(session, f"firewall-cmd --permanent --remove-port={port}/tcp >/dev/null && firewall-cmd --reload >/dev/null", check=False)


def parse_domains(raw: str) -> list[str]:
    domains = list(dict.fromkeys(x.lower().strip().rstrip(".") for x in re.split(r"[\s,]+", raw) if x.strip()))
    if not domains or any(not DOMAIN_RE.fullmatch(x) for x in domains):
        raise ValueError("Enter one or more valid domain names")
    return domains


def parse_hosts(raw: str) -> list[str]:
    hosts = list(dict.fromkeys(x.lower().strip().rstrip(".") for x in re.split(r"[\s,]+", raw) if x.strip()))
    for host in hosts:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not DOMAIN_RE.fullmatch(host):
                raise ValueError(f"Invalid clean address: {host}")
    if not hosts:
        raise ValueError("Enter at least one clean CDN address")
    return hosts


def points_to_server(domain: str, public_ip: str) -> bool:
    try:
        return public_ip in {x[4][0] for x in socket.getaddrinfo(domain, None)}
    except socket.gaierror:
        return False


def ensure_certificate(session: ServerSession, domain: str) -> tuple[str, str]:
    cert = f"/root/cert/{domain}/fullchain.pem"
    key = f"/root/cert/{domain}/privkey.pem"
    if remote(session, f"test -s '{cert}' -a -s '{key}' && echo yes", check=False).strip() == "yes":
        return cert, key
    options = api(session, "GET", "/inbounds/options")["obj"]
    paused = [x for x in options if int(x.get("port", 0)) == 80 and x.get("enable", False)]
    for inbound in paused:
        api(session, "POST", f"/inbounds/setEnable/{inbound['id']}", {"enable": False})
    try:
        script = f'''set -e
if ss -lntH 'sport = :80' | grep -q .; then echo 'Port 80 is occupied outside 3x-ui' >&2; exit 1; fi
printf '20\n1\n{domain}\n80\nn\nn\n0\n0\n' | timeout 300 /usr/bin/x-ui >/tmp/inbound-gen-acme.log 2>&1 || true
test -s '{cert}' -a -s '{key}' || {{ tail -n 40 /tmp/inbound-gen-acme.log >&2; exit 1; }}'''
        remote(session, script)
    finally:
        for inbound in paused:
            for _ in range(10):
                try:
                    api(session, "POST", f"/inbounds/setEnable/{inbound['id']}", {"enable": True})
                    break
                except Exception:
                    time.sleep(1)
    return cert, key


def smart_candidates(domain: str, direct: bool, clean: list[str], cert: str = "", key: str = "") -> list[dict]:
    path = "/" + secrets.token_hex(5)
    if direct:
        return [
            {"template": "vless-reality-tcp", "address": domain, "host": "", "sni": "www.microsoft.com", "path": "/", "reality_target": "www.microsoft.com:443"},
            {"template": "vless-httpupgrade-none", "address": clean[0], "host": domain, "sni": "", "path": path},
            {"template": "vless-httpupgrade-none", "address": domain, "host": domain, "sni": "", "path": path},
        ]
    tls = {"host": domain, "sni": domain, "path": path + "?ed=2048", "certificate": cert, "private_key": key}
    return [
        {"template": "vless-ws-tls", "address": clean[0], **tls},
        {"template": "vless-ws-tls", "address": domain, **tls},
        {"template": "vless-xhttp-tls", "address": clean[0], "mode": "auto", **tls},
        {"template": "vless-httpupgrade-none", "address": clean[0], "host": domain, "sni": "", "path": path},
    ]


def remove_smart_attempt(session: ServerSession, remark: str) -> None:
    try:
        options = api(session, "GET", "/inbounds/options")["obj"]
        target = next((x for x in options if x.get("remark") == remark), None)
        if target:
            api(session, "POST", f"/inbounds/del/{target['id']}")
    except Exception:
        pass


def inbound_payload(session: ServerSession, form: dict) -> tuple[dict, str, str]:
    template = str(form.get("template", ""))
    remark = str(form.get("remark", "")).strip()
    port = int(form.get("inbound_port", 0))
    address = str(form.get("address", "")).strip()
    host = str(form.get("host", "")).strip()
    sni = str(form.get("sni", "")).strip() or host or address
    path = str(form.get("path", "/")).strip() or "/"
    if not remark or not address or not 1 <= port <= 65535:
        raise ValueError("Remark, share address, and a valid port are required")
    protocol = "vmess" if template.startswith("vmess") else "trojan" if template.startswith("trojan") else "vless"
    settings = {"clients": []}
    if protocol == "vless":
        settings.update({"decryption": "none", "encryption": "none"})
    stream: dict
    if template == "vless-httpupgrade-none":
        stream = {"network": "httpupgrade", "security": "none", "httpupgradeSettings": {"acceptProxyProtocol": False, "path": path, "host": host, "headers": {}}}
    elif template in ("vless-ws-tls", "vmess-ws-tls", "trojan-ws-tls"):
        cert, key = str(form.get("certificate", "")).strip(), str(form.get("private_key", "")).strip()
        if not cert or not key:
            raise ValueError("TLS certificate and private-key paths are required")
        stream = {"network": "ws", "security": "tls", "wsSettings": {"acceptProxyProtocol": False, "path": path, "host": host, "headers": {}}, "tlsSettings": {"serverName": sni, "minVersion": "1.2", "maxVersion": "1.3", "alpn": ["http/1.1"], "certificates": [{"certificateFile": cert, "keyFile": key, "usage": "encipherment"}], "settings": {"fingerprint": str(form.get("fingerprint", "chrome"))}}}
    elif template == "vless-xhttp-tls":
        cert, key = str(form.get("certificate", "")).strip(), str(form.get("private_key", "")).strip()
        if not cert or not key:
            raise ValueError("TLS certificate and private-key paths are required")
        stream = {"network": "xhttp", "security": "tls", "xhttpSettings": {"path": path, "host": host, "mode": str(form.get("mode", "auto"))}, "tlsSettings": {"serverName": sni, "minVersion": "1.2", "maxVersion": "1.3", "alpn": ["h2", "http/1.1"], "certificates": [{"certificateFile": cert, "keyFile": key, "usage": "encipherment"}], "settings": {"fingerprint": str(form.get("fingerprint", "chrome"))}}}
    elif template == "vless-reality-tcp":
        target = str(form.get("reality_target", "")).strip()
        if not target or not sni:
            raise ValueError("REALITY target and SNI are required")
        output = remote(session, "/usr/local/x-ui/bin/xray-linux-amd64 x25519")
        values = dict(line.split(": ", 1) for line in output.splitlines() if ": " in line)
        private = values["PrivateKey"]
        public = values.get("Password") or values.get("Password (PublicKey)")
        stream = {"network": "tcp", "security": "reality", "tcpSettings": {"header": {"type": "none"}}, "realitySettings": {"show": False, "xver": 0, "target": target, "serverNames": [sni], "privateKey": private, "shortIds": [secrets.token_hex(8)], "settings": {"publicKey": public, "fingerprint": str(form.get("fingerprint", "chrome")), "serverName": sni, "spiderX": "/"}}}
    elif template == "trojan-tcp-tls":
        cert, key = str(form.get("certificate", "")).strip(), str(form.get("private_key", "")).strip()
        if not cert or not key:
            raise ValueError("TLS certificate and private-key paths are required")
        stream = {"network": "tcp", "security": "tls", "tcpSettings": {"header": {"type": "none"}}, "tlsSettings": {"serverName": sni, "minVersion": "1.2", "maxVersion": "1.3", "alpn": ["h2", "http/1.1"], "certificates": [{"certificateFile": cert, "keyFile": key, "usage": "encipherment"}], "settings": {"fingerprint": str(form.get("fingerprint", "chrome"))}}}
    else:
        raise ValueError("Unsupported inbound template")
    return {"enable": True, "remark": remark, "listen": "", "port": port, "protocol": protocol, "expiryTime": 0, "total": 0, "trafficReset": "never", "shareAddrStrategy": "custom", "shareAddr": address, "settings": settings, "streamSettings": stream, "sniffing": {"enabled": False}}, PROJECT_CLIENT, protocol


def project_client_link(session: ServerSession, inbound_id: int, protocol: str, port: int) -> str:
    email = urllib.parse.quote(PROJECT_CLIENT)
    try:
        client = api(session, "GET", f"/clients/get/{email}")["obj"]
        if inbound_id not in (client.get("inboundIds") or []):
            api(session, "POST", f"/clients/{email}/attach", {"inboundIds": [inbound_id]})
    except RuntimeError as exc:
        if "record not found" not in str(exc).lower():
            raise
        api(session, "POST", "/clients/add", {"client": {"email": PROJECT_CLIENT, "totalGB": 0, "expiryTime": 0, "tgId": 0, "limitIp": 0, "enable": True}, "inboundIds": [inbound_id]})
    links = api(session, "GET", f"/clients/links/{email}")["obj"]
    prefix = protocol + "://"
    for link in links:
        if not link.startswith(prefix):
            continue
        if protocol == "vmess":
            data = json.loads(base64.b64decode(link.removeprefix(prefix) + "=" * (-len(link.removeprefix(prefix)) % 4)))
            link_port = int(data["port"])
        else:
            link_port = urllib.parse.urlsplit(link).port
        if link_port == port:
            return link
    raise RuntimeError(f"No {protocol} link was generated for {PROJECT_CLIENT} on port {port}")


def session_from(data: dict) -> ServerSession:
    sid = str(data.get("session", ""))
    with LOCK:
        session = SESSIONS.get(sid)
    if not session:
        raise PermissionError("Session expired; detect the server again")
    return session


def create_and_test(data: dict) -> dict:
    session = session_from(data)
    template = str(data.get("template", ""))
    requested = int(data.get("inbound_port", 0))
    options = api(session, "GET", "/inbounds/options")["obj"]
    port, automatic = choose_port(session, template, requested, {int(x["port"]) for x in options})
    payload, _, protocol = inbound_payload(session, {**data, "inbound_port": port})
    firewall = open_firewall(session, port)
    inbound_id = None
    try:
        result = api(session, "POST", "/inbounds/add", payload)
        inbound_id = (result.get("obj") or {}).get("id") if isinstance(result.get("obj"), dict) else None
        if not inbound_id:
            options = api(session, "GET", "/inbounds/options")["obj"]
            inbound_id = next(x["id"] for x in options if x["remark"] == payload["remark"] and x["port"] == port)
        uri = project_client_link(session, inbound_id, protocol, port)
        test = test_link(uri, XRAY, session.public_ip)
    except Exception:
        if inbound_id:
            try:
                api(session, "POST", f"/inbounds/setEnable/{inbound_id}", {"enable": False})
            except Exception:
                pass
        rollback_firewall(session, port, firewall)
        raise
    if not test["working"]:
        api(session, "POST", f"/inbounds/setEnable/{inbound_id}", {"enable": False})
        rollback_firewall(session, port, firewall)
    return {"inbound_id": inbound_id, "remark": payload["remark"], "port": port, "port_automatic": automatic, "firewall": firewall, "protocol": protocol, "working": test["working"], "stability": test["stability"], "runs": test["runs"], "disabled_after_failure": not test["working"]}


def smart_build(data: dict) -> dict:
    session = session_from(data)
    domains = parse_domains(str(data.get("domains", "")))
    clean = parse_hosts(str(data.get("clean_addresses", "www.speedtest.net")))
    results = []
    for domain in domains:
        direct = points_to_server(domain, session.public_ip)
        cert = key = cert_error = ""
        if not direct:
            try:
                cert, key = ensure_certificate(session, domain)
            except Exception as exc:
                cert_error = str(exc)[:300]
        candidates = smart_candidates(domain, direct, clean, cert, key)
        if not cert:
            candidates = [x for x in candidates if "tls" not in x["template"]]
        attempts = []
        for index, candidate in enumerate(candidates, 1):
            remark = f"Smart {domain} {index}"
            form = {**data, **candidate, "inbound_port": 0, "remark": remark, "fingerprint": data.get("fingerprint", "chrome")}
            try:
                outcome = create_and_test(form)
                attempts.append({"template": candidate["template"], "address": candidate["address"], "host": candidate.get("host", ""), "sni": candidate.get("sni", ""), "port": outcome["port"], "working": outcome["working"], "stability": outcome["stability"]})
                if outcome["working"]:
                    break
                remove_smart_attempt(session, remark)
            except Exception as exc:
                attempts.append({"template": candidate["template"], "address": candidate["address"], "host": candidate.get("host", ""), "sni": candidate.get("sni", ""), "working": False, "error": str(exc)[:300]})
                remove_smart_attempt(session, remark)
        results.append({"domain": domain, "kind": "direct" if direct else "cdn", "certificate": bool(cert), "certificate_error": cert_error, "working": any(x.get("working") for x in attempts), "attempts": attempts})
    return {"results": results}


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC), **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'")
        super().end_headers()

    def log_message(self, fmt, *args):
        print(f"{self.client_address[0]} {fmt % args}")

    def json_response(self, status: int, data: dict):
        raw = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json; charset=utf-8"); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_BODY:
                raise ValueError("Invalid request size")
            data = json.loads(self.rfile.read(length))
            if self.path == "/api/detect":
                state, result = discover(data)
                return self.json_response(409 if state == "trust" else 200, {"ok": state == "ok", **result})
            if self.path == "/api/create-test":
                return self.json_response(200, {"ok": True, **create_and_test(data)})
            if self.path == "/api/smart-build":
                return self.json_response(200, {"ok": True, **smart_build(data)})
            if self.path == "/api/inbounds":
                session = session_from(data)
                return self.json_response(200, {"ok": True, "inbounds": api(session, "GET", "/inbounds/options")["obj"]})
            self.json_response(404, {"ok": False, "error": "Not found"})
        except PermissionError as exc:
            self.json_response(401, {"ok": False, "error": str(exc)})
        except Exception as exc:
            self.json_response(400, {"ok": False, "error": str(exc)[:1000]})


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 8765), Handler)
    print("Inbound Gen: http://127.0.0.1:8765")
    threading.Timer(.8, lambda: webbrowser.open("http://127.0.0.1:8765")).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
