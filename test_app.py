import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

import app
from tester import client_config, self_test


class AppTests(unittest.TestCase):
    def setUp(self):
        self.session = app.ServerSession("example.com", 22, "root", "pw", "SHA256:test", "https://127.0.0.1/api/panel/api", "token", "203.0.113.1", 0)
        self.base = {"remark": "Test", "inbound_port": 443, "address": "direct.example.com", "host": "sni.example.com", "sni": "sni.example.com", "path": "/ws", "certificate": "/cert/fullchain.pem", "private_key": "/cert/privkey.pem", "fingerprint": "firefox"}

    def test_vless_ws_tls_payload(self):
        payload, sub_id, protocol = app.inbound_payload(self.session, {**self.base, "template": "vless-ws-tls"})
        self.assertEqual(protocol, "vless")
        self.assertEqual(payload["streamSettings"]["wsSettings"]["path"], "/ws")
        self.assertEqual(payload["streamSettings"]["tlsSettings"]["settings"]["fingerprint"], "firefox")
        self.assertTrue(sub_id)

    def test_panel_generates_protocol_secrets_for_shared_client(self):
        vmess, _, _ = app.inbound_payload(self.session, {**self.base, "template": "vmess-ws-tls"})
        trojan, _, protocol = app.inbound_payload(self.session, {**self.base, "template": "trojan-ws-tls"})
        self.assertEqual(vmess["settings"]["clients"], [])
        self.assertEqual(trojan["settings"]["clients"], [])
        self.assertEqual(protocol, "trojan")
        self.assertEqual(trojan["streamSettings"]["network"], "ws")

    def test_project_client_is_reused_and_attached(self):
        calls = []
        def fake_api(_session, method, path, body=None):
            calls.append((method, path, body))
            if path == "/clients/get/inbound-gen":
                return {"obj": {"inboundIds": [3]}}
            if path == "/clients/links/inbound-gen":
                return {"obj": ["vless://id@example.com:443?type=tcp"]}
            return {"success": True}
        with patch("app.api", side_effect=fake_api):
            link = app.project_client_link(self.session, 4, "vless", 443)
        self.assertEqual(link, "vless://id@example.com:443?type=tcp")
        self.assertIn(("POST", "/clients/inbound-gen/attach", {"inboundIds": [4]}), calls)

    def test_local_link_parser(self):
        self_test()
        config = client_config("trojan://pw@example.com:443?type=tcp&security=tls&sni=example.com", 31000)
        self.assertEqual(config["outbounds"][0]["protocol"], "trojan")

    def test_auto_port_prefers_tls_ports_and_skips_used(self):
        with patch("app.port_in_use", side_effect=lambda _session, port: port == 8443):
            port, automatic = app.choose_port(self.session, "vless-reality-tcp", 0, {443})
        self.assertEqual(port, 2053)
        self.assertTrue(automatic)

    def test_failed_relay_rolls_back_new_firewall_rule(self):
        app.SESSIONS["test"] = self.session
        def fake_api(_session, method, path, body=None):
            if path == "/inbounds/options":
                return {"obj": []}
            if path == "/inbounds/add":
                return {"obj": {"id": 9}}
            return {"success": True}
        form = {**self.base, "session": "test", "template": "vless-httpupgrade-none", "inbound_port": 0}
        with patch("app.api", side_effect=fake_api), patch("app.choose_port", return_value=(80, True)), patch("app.open_firewall", return_value="ufw-added"), patch("app.project_client_link", return_value="vless://test"), patch("app.rollback_firewall") as rollback, patch("app.test_link", return_value={"working": False, "stability": "0/3", "runs": []}):
            result = app.create_and_test(form)
        rollback.assert_called_once_with(self.session, 80, "ufw-added")
        self.assertTrue(result["disabled_after_failure"])
        app.SESSIONS.pop("test", None)

    def test_smart_matrix_matches_reference_order(self):
        direct = app.smart_candidates("direct.example.com", True, ["www.speedtest.net"])
        cdn = app.smart_candidates("cdn.example.com", False, ["www.speedtest.net"], "/cert.pem", "/key.pem")
        self.assertEqual(direct[0]["template"], "vless-reality-tcp")
        self.assertEqual(cdn[0]["template"], "vless-ws-tls")
        self.assertEqual(cdn[0]["address"], "www.speedtest.net")
        self.assertEqual(cdn[0]["sni"], "cdn.example.com")
        self.assertEqual(app.parse_hosts("199.232.78.159, www.speedtest.net"), ["199.232.78.159", "www.speedtest.net"])

    def test_smart_cleanup_deletes_only_exact_trial(self):
        calls = []
        def fake_api(_session, method, path, body=None):
            calls.append((method, path))
            return {"obj": [{"id": 7, "remark": "Smart cdn.example.com 1"}, {"id": 8, "remark": "Keep me"}]}
        with patch("app.api", side_effect=fake_api):
            app.remove_smart_attempt(self.session, "Smart cdn.example.com 1")
        self.assertIn(("POST", "/inbounds/del/7"), calls)
        self.assertNotIn(("POST", "/inbounds/del/8"), calls)


if __name__ == "__main__":
    unittest.main()
