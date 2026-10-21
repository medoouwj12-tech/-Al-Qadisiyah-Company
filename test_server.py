"""Integration checks for authentication, role boundaries, and stock safety."""
import http.client
import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

import server


class AppIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.original_db = server.DB_PATH
        server.DB_PATH = Path(self.temp.name) / "test.db"
        server.initialize()
        server.create_manager("manager", "مدير الاختبار", "TestManager@2026!")
        with server.connect() as db:
            db.execute("INSERT INTO users(username,display_name,password_hash,role,permissions) VALUES(?,?,?,'employee',?)",
                       ("worker", "موظف الاختبار", server.password_hash("TestWorker@2026!"), json.dumps(server.DEFAULT_PERMISSIONS)))
            db.execute("INSERT INTO suppliers(name) VALUES('مورد الاختبار')")
            db.execute("INSERT INTO materials(name,sku,stock,min_stock,purchase_price,sale_price,supplier_id,warehouse_id) VALUES(?,?,?,?,?,?,?,?)",
                       ("رخام اختبار", "T-001", 10, 2, 100, 250, 1, 1))
        self.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.AppHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.httpd.server_address[1]

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.DB_PATH = self.original_db
        self.temp.cleanup()

    def request(self, method, path, payload=None, cookie=None, extra_headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        body = json.dumps(payload or {}, ensure_ascii=False).encode("utf-8") if method == "POST" else None
        headers = {"Content-Type": "application/json"}
        if cookie:
            headers["Cookie"] = cookie
        headers.update(extra_headers or {})
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        raw = response.read()
        result = json.loads(raw) if raw else {}
        response_headers = dict(response.getheaders())
        conn.close()
        return response.status, result, response_headers

    def login(self, username, password):
        status, data, headers = self.request("POST", "/api/login", {"username": username, "password": password})
        self.assertEqual(status, 200)
        return headers["Set-Cookie"].split(";", 1)[0]

    def test_employee_never_receives_sale_prices_and_is_denied_manager_apis(self):
        cookie = self.login("worker", "TestWorker@2026!")
        for path, key in (("/api/materials", "materials"), ("/api/movements", "movements")):
            status, data, _ = self.request("GET", path, cookie=cookie)
            self.assertEqual(status, 200)
            for row in data[key]:
                self.assertNotIn("sale_price", row)
                self.assertNotIn("unit_sale", row)
        for path in ("/api/users", "/api/audit", "/api/reports", "/api/customers"):
            status, _, _ = self.request("GET", path, cookie=cookie)
            self.assertEqual(status, 403, path)

    def test_manager_only_can_read_sale_prices(self):
        cookie = self.login("manager", "TestManager@2026!")
        status, data, _ = self.request("GET", "/api/materials", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual(data["materials"][0]["sale_price"], 250)

    def test_dashboard_stats_are_scoped_and_financial_totals_are_manager_only(self):
        employee = self.login("worker", "TestWorker@2026!")
        status, data, _ = self.request("GET", "/api/dashboard", cookie=employee)
        self.assertEqual(status, 200)
        self.assertEqual(data["stats"]["sales_count"], 0)
        self.assertNotIn("today_revenue", data["stats"])
        self.assertNotIn("today_profit", data["stats"])
        manager = self.login("manager", "TestManager@2026!")
        status, data, _ = self.request("GET", "/api/dashboard", cookie=manager)
        self.assertEqual(status, 200)
        self.assertIn("today_revenue", data["stats"])

    def test_material_detail_shows_supplier_purchase_history_without_sale_price_leak(self):
        employee = self.login("worker", "TestWorker@2026!")
        status, _, _ = self.request("POST", "/api/movements", {"type":"receipt","material_id":1,"quantity":3,"unit_cost":75,"party":"مورد بديل"}, employee, {"Idempotency-Key":"receipt-detail-123456"})
        self.assertEqual(status, 201)
        status, data, _ = self.request("GET", "/api/materials/1", cookie=employee)
        self.assertEqual(status, 200)
        self.assertEqual(data["supply_history"][0]["supplier"], "مورد بديل")
        self.assertEqual(data["supply_history"][0]["unit_cost"], 75)
        self.assertNotIn("sale_price", data["material"])
        self.assertNotIn("unit_sale", data["history"][0])
        manager = self.login("manager", "TestManager@2026!")
        status, data, _ = self.request("GET", "/api/materials/1", cookie=manager)
        self.assertEqual(status, 200)
        self.assertEqual(data["material"]["sale_price"], 250)
        self.assertEqual(data["supply_history"][0]["supplier"], "مورد بديل")

    def test_brand_logo_assets_are_served(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/assets/alqadsia-logo.jpg")
        response = conn.getresponse()
        body = response.read()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader("Content-Type"), "image/jpeg; charset=utf-8")
        self.assertTrue(body.startswith(b"\xff\xd8"))
        conn.close()

    def test_stock_changes_are_transactional_and_never_go_negative(self):
        cookie = self.login("worker", "TestWorker@2026!")
        key = "sale-attempt-123456"
        status, _, _ = self.request("POST", "/api/movements", {"type":"sale","material_id":1,"quantity":11,"party":"عميل"}, cookie, {"Idempotency-Key":key})
        self.assertEqual(status, 400)
        with server.connect() as db:
            self.assertEqual(db.execute("SELECT stock FROM materials WHERE id=1").fetchone()[0], 10)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM movements").fetchone()[0], 0)
        key = "sale-success-123456"
        payload = {"type":"sale","material_id":1,"quantity":3,"party":"عميل"}
        status, _, _ = self.request("POST", "/api/movements", payload, cookie, {"Idempotency-Key":key})
        self.assertEqual(status, 201)
        status, data, _ = self.request("POST", "/api/movements", payload, cookie, {"Idempotency-Key":key})
        self.assertEqual(status, 200)
        self.assertTrue(data["duplicate"])
        with server.connect() as db:
            self.assertEqual(db.execute("SELECT stock FROM materials WHERE id=1").fetchone()[0], 7)

    def test_employee_cannot_mutate_master_data_or_change_role(self):
        cookie = self.login("worker", "TestWorker@2026!")
        status, _, _ = self.request("POST", "/api/materials", {"name":"سرية","sku":"X"}, cookie)
        self.assertEqual(status, 403)
        status, _, _ = self.request("POST", "/api/users", {"username":"boss","display_name":"مدير","password":"GoodPassword@2026","role":"manager"}, cookie)
        self.assertEqual(status, 403)

    def test_login_events_are_audited(self):
        self.request("POST", "/api/login", {"username":"missing","password":"incorrect"})
        cookie = self.login("manager", "TestManager@2026!")
        status, data, _ = self.request("GET", "/api/audit", cookie=cookie)
        self.assertEqual(status, 200)
        actions = [event["action"] for event in data["events"]]
        self.assertIn("login_failed", actions)
        self.assertIn("login", actions)


if __name__ == "__main__":
    unittest.main()
