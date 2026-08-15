from __future__ import annotations

import base64
import json
import re
import socket
import subprocess
import tempfile
import time
import urllib.parse
from pathlib import Path

SECRET_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}\b|(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-])")


def _one(query: dict[str, list[str]], key: str, default: str = "") -> str:
    return query.get(key, [default])[0]


def _stream(parsed: urllib.parse.SplitResult, query: dict[str, list[str]]) -> dict:
    network = _one(query, "type", "tcp")
    security = _one(query, "security", "none")
    host = _one(query, "host")
    path = urllib.parse.unquote(_one(query, "path", "/"))
    stream: dict = {"network": network, "security": security}
    if network in ("tcp", "raw"):
        stream["tcpSettings"] = {"header": {"type": _one(query, "headerType", "none")}}
    elif network == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host} if host else {}}
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": path, "host": host}
    elif network == "xhttp":
        stream["xhttpSettings"] = {"path": path, "host": host, "mode": _one(query, "mode", "auto")}
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": _one(query, "serviceName", path.lstrip("/"))}
    else:
        raise ValueError(f"Unsupported local test transport: {network}")
    if security == "tls":
        tls: dict = {
            "serverName": _one(query, "sni", parsed.hostname or ""),
            "fingerprint": _one(query, "fp", "chrome"),
            "allowInsecure": _one(query, "allowInsecure") == "1",
        }
        if alpn := [x for x in _one(query, "alpn").split(",") if x]:
            tls["alpn"] = alpn
        stream["tlsSettings"] = tls
    elif security == "reality":
        stream["realitySettings"] = {
            "serverName": _one(query, "sni", parsed.hostname or ""),
            "fingerprint": _one(query, "fp", "chrome"),
            "password": _one(query, "pbk") or _one(query, "password"),
            "shortId": _one(query, "sid"),
            "spiderX": urllib.parse.unquote(_one(query, "spx", "/")),
        }
    return stream


def client_config(uri: str, socks_port: int) -> dict:
    uri = uri.strip()
    if uri.startswith("vmess://"):
        raw = uri.removeprefix("vmess://")
        data = json.loads(base64.b64decode(raw + "=" * (-len(raw) % 4)))
        parsed = urllib.parse.urlsplit(f"dummy://u@{data['add']}:{data['port']}")
        query = {k: [str(v)] for k, v in {
            "type": data.get("net", "tcp"), "security": data.get("tls", "none"),
            "host": data.get("host", ""), "path": data.get("path", "/"),
            "headerType": data.get("type", "none"), "sni": data.get("sni", data["add"]),
            "fp": data.get("fp", "chrome"), "alpn": data.get("alpn", ""),
        }.items()}
        outbound = {"protocol": "vmess", "settings": {"vnext": [{
            "address": data["add"], "port": int(data["port"]),
            "users": [{"id": data["id"], "security": data.get("scy", "auto"), "alterId": int(data.get("aid", 0))}],
        }]}, "streamSettings": _stream(parsed, query)}
    else:
        parsed = urllib.parse.urlsplit(uri)
        if parsed.scheme not in ("vless", "trojan") or not parsed.username or not parsed.hostname or not parsed.port:
            raise ValueError("Expected a complete VLESS, VMess, or Trojan share link")
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        stream = _stream(parsed, query)
        if parsed.scheme == "vless":
            user = {"id": urllib.parse.unquote(parsed.username), "encryption": _one(query, "encryption", "none")}
            if flow := _one(query, "flow"):
                user["flow"] = flow
            outbound = {"protocol": "vless", "settings": {"vnext": [{"address": parsed.hostname, "port": parsed.port, "users": [user]}]}, "streamSettings": stream}
        else:
            outbound = {"protocol": "trojan", "settings": {"servers": [{"address": parsed.hostname, "port": parsed.port, "password": urllib.parse.unquote(parsed.username)}]}, "streamSettings": stream}
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks", "settings": {"udp": True}}],
        "outbounds": [outbound],
    }


def _wait_port(port: int, process: subprocess.Popen, timeout: float = 8) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if process.poll() is not None:
            raise RuntimeError("Local Xray exited before opening SOCKS")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.2):
                return
        except OSError:
            time.sleep(.1)
    raise TimeoutError("Local Xray SOCKS listener did not start")


def _curl(port: int, url: str, output: Path, upload: Path | None = None) -> dict:
    marker = "__METRICS__"
    metric = "%{speed_upload}" if upload else "%{speed_download}"
    command = ["curl.exe", "--noproxy", "", "--socks5-hostname", f"127.0.0.1:{port}", "-sS", "--max-time", "20", "-o", str(output), "-w", marker + "%{http_code}|%{time_connect}|%{time_starttransfer}|" + metric]
    if upload:
        command += ["--data-binary", f"@{upload}"]
    command.append(url)
    run = subprocess.run(command, text=True, capture_output=True, timeout=25)
    values = run.stdout.rsplit(marker, 1)[-1].split("|") if marker in run.stdout else []
    return {
        "ok": run.returncode == 0 and len(values) == 4 and values[0] == "200",
        "http": int(values[0]) if len(values) == 4 and values[0].isdigit() else 0,
        "connect_ms": round(float(values[1]) * 1000, 2) if len(values) == 4 else None,
        "ttfb_ms": round(float(values[2]) * 1000, 2) if len(values) == 4 else None,
        "bytes_per_s": round(float(values[3])) if len(values) == 4 else None,
        "error": run.stderr.strip()[-300:],
    }


def test_link(uri: str, xray: Path, expected_ip: str, runs: int = 3) -> dict:
    if not xray.is_file():
        raise FileNotFoundError(f"Xray not found: {xray}")
    with tempfile.TemporaryDirectory(prefix="inbound-gen-") as folder:
        root = Path(folder)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        config = root / "client.json"
        config.write_text(json.dumps(client_config(uri, port)), encoding="utf-8")
        log_path = root / "xray.log"
        with log_path.open("w+", encoding="utf-8") as log:
            process = subprocess.Popen([str(xray), "run", "-config", str(config)], stdout=log, stderr=subprocess.STDOUT, text=True)
            evidence = []
            try:
                _wait_port(port, process)
                upload_source = root / "upload.bin"
                upload_source.write_bytes(b"x" * 100_000)
                for index in range(runs):
                    trace_file, ip_file = root / f"trace-{index}.txt", root / f"ip-{index}.txt"
                    trace = _curl(port, "https://www.cloudflare.com/cdn-cgi/trace", trace_file)
                    ip_check = _curl(port, "https://api.ipify.org", ip_file)
                    download = _curl(port, "https://speed.cloudflare.com/__down?bytes=100000", root / f"down-{index}.bin")
                    upload = _curl(port, "https://speed.cloudflare.com/__up", root / f"up-{index}.txt", upload_source)
                    trace_ip = next((line[3:].strip() for line in trace_file.read_text(errors="ignore").splitlines() if line.startswith("ip=")), "") if trace_file.exists() else ""
                    ipify = ip_file.read_text(errors="ignore").strip() if ip_file.exists() else ""
                    passed = trace["ok"] and ip_check["ok"] and download["ok"] and upload["ok"] and trace_ip == expected_ip and ipify == expected_ip
                    evidence.append({"run": index + 1, "passed": passed, "exit_ip": trace_ip, "trace": trace, "download": download, "upload": upload})
                    if not passed:
                        break
            finally:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                log.flush(); log.seek(0)
                safe_log = SECRET_RE.sub("REDACTED", log.read()[-2000:])
    return {"working": len(evidence) == runs and all(x["passed"] for x in evidence), "stability": f"{sum(x['passed'] for x in evidence)}/{runs}", "runs": evidence, "log": safe_log}


def self_test() -> None:
    uri = "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=ws&security=tls&host=cdn.example.com&sni=cdn.example.com&path=%2Fws&fp=firefox"
    config = client_config(uri, 31001)
    stream = config["outbounds"][0]["streamSettings"]
    assert stream["network"] == "ws" and stream["tlsSettings"]["fingerprint"] == "firefox"

