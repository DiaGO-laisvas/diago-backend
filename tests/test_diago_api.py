"""DiaGO backend regression tests."""
import pytest


# ----- Root health -----
def test_root(api_client, base_url):
    r = api_client.get(f"{base_url}/api/")
    assert r.status_code == 200
    data = r.json()
    assert data.get("message") == "DiaGO API ready"
    assert data.get("service_price_eur") == 25.0
    assert data.get("deposit_eur") == 25.0


# ----- Session CRUD -----
class TestSessions:
    def test_create_session_with_uuid(self, api_client, base_url):
        r = api_client.post(f"{base_url}/api/sessions", json={})
        assert r.status_code == 200, r.text
        s = r.json()
        assert s["id"] and len(s["id"]) >= 32
        assert s["status"] == "created"
        assert s["payment_status"] == "pending"
        assert s["station_id"] == "STATION-01"
        assert "_id" not in s

    def test_update_session_persists_new_fields(self, api_client, base_url):
        # Iteration 3: new vehicle schema — vin/fuel/power_kw/detection_method
        r = api_client.post(f"{base_url}/api/sessions", json={})
        sid = r.json()["id"]
        payload = {
            "vehicle": {
                "knows_port": True,
                "vin": "WAUZZZ8K9JA123456",
                "brand": "TEST_Audi",
                "model": "A4 2.0 TDI",
                "year": "2018",
                "fuel": "Dyzelinas",
                "power_kw": "140",
                "detection_method": "vin_auto",
            },
            "contact": {"method": "email", "value": "test@diago.lt"},
        }
        r = api_client.put(f"{base_url}/api/sessions/{sid}", json=payload)
        assert r.status_code == 200, r.text
        upd = r.json()
        v = upd["vehicle"]
        assert v["brand"] == "TEST_Audi"
        assert v["vin"] == "WAUZZZ8K9JA123456"
        assert v["fuel"] == "Dyzelinas"
        assert v["power_kw"] == "140"
        assert v["detection_method"] == "vin_auto"
        assert v["knows_port"] is True
        assert upd["contact"]["method"] == "email"
        # Removed fields no longer part of schema (iter 5)
        assert "service_light" not in v
        assert "service_done" not in v
        assert "plate" not in v
        assert "diag_type" not in v
        # GET-verify persistence
        g = api_client.get(f"{base_url}/api/sessions/{sid}")
        assert g.status_code == 200
        gv = g.json()["vehicle"]
        assert gv["vin"] == "WAUZZZ8K9JA123456"
        assert gv["power_kw"] == "140"
        assert gv["detection_method"] == "vin_auto"
        assert "_id" not in g.json()

    def test_update_session_manual_detection(self, api_client, base_url):
        r = api_client.post(f"{base_url}/api/sessions", json={})
        sid = r.json()["id"]
        payload = {
            "vehicle": {
                "brand": "TEST_BMW",
                "model": "320d",
                "year": "2020",
                "fuel": "Dyzelinas",
                "power_kw": "140",
                "detection_method": "manual",
            },
        }
        r = api_client.put(f"{base_url}/api/sessions/{sid}", json=payload)
        assert r.status_code == 200, r.text
        v = r.json()["vehicle"]
        assert v["detection_method"] == "manual"
        assert v.get("vin") in (None, "")

    def test_update_nonexistent_returns_404(self, api_client, base_url):
        r = api_client.put(f"{base_url}/api/sessions/nonexistent-xyz", json={"vehicle": {"brand": "X"}})
        assert r.status_code == 404


# ----- Checkout flow -----
class TestCheckout:
    def test_create_checkout_returns_url(self, api_client, base_url):
        r = api_client.post(f"{base_url}/api/sessions", json={})
        sid = r.json()["id"]
        r = api_client.post(
            f"{base_url}/api/checkout/session",
            json={"session_id": sid, "origin_url": base_url},
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert data.get("url", "").startswith("http")
        assert data.get("session_id")
        # verify transaction persisted + session linked
        g = api_client.get(f"{base_url}/api/sessions/{sid}").json()
        assert g["checkout_session_id"] == data["session_id"]

    def test_create_checkout_bad_session(self, api_client, base_url):
        r = api_client.post(
            f"{base_url}/api/checkout/session",
            json={"session_id": "does-not-exist", "origin_url": base_url},
        )
        assert r.status_code == 404

    def test_checkout_status_polls(self, api_client, base_url):
        r = api_client.post(f"{base_url}/api/sessions", json={})
        sid = r.json()["id"]
        r = api_client.post(
            f"{base_url}/api/checkout/session",
            json={"session_id": sid, "origin_url": base_url},
        )
        cs_id = r.json()["session_id"]
        st = api_client.get(f"{base_url}/api/checkout/status/{cs_id}")
        assert st.status_code == 200, st.text
        body = st.json()
        assert "status" in body and "payment_status" in body
        # Should be unpaid/pending/initiated initially (DB fallback)
        assert body["payment_status"] in (
            "unpaid", "no_payment_required", "paid", "pending", "initiated",
        )

    def test_checkout_status_404_for_unknown(self, api_client, base_url):
        st = api_client.get(f"{base_url}/api/checkout/status/cs_does_not_exist_xyz")
        assert st.status_code == 404

    def test_checkout_confirm_marks_paid_and_propagates(self, api_client, base_url):
        # Create session + checkout
        r = api_client.post(f"{base_url}/api/sessions", json={})
        sid = r.json()["id"]
        r = api_client.post(
            f"{base_url}/api/checkout/session",
            json={"session_id": sid, "origin_url": base_url},
        )
        assert r.status_code == 200, r.text
        cs_id = r.json()["session_id"]

        # Confirm (trust-the-redirect)
        c = api_client.post(f"{base_url}/api/checkout/confirm/{cs_id}")
        assert c.status_code == 200, c.text
        cbody = c.json()
        assert cbody.get("ok") is True
        assert cbody.get("confirmed") is True or cbody.get("already_paid") is True

        # Status should now reflect paid
        st = api_client.get(f"{base_url}/api/checkout/status/{cs_id}")
        assert st.status_code == 200, st.text
        assert st.json()["payment_status"] == "paid"

        # Parent diagnostic session should also be paid
        sess = api_client.get(f"{base_url}/api/sessions/{sid}").json()
        assert sess["payment_status"] == "paid"
        assert sess["status"] == "paid"

        # Idempotent second confirm
        c2 = api_client.post(f"{base_url}/api/checkout/confirm/{cs_id}")
        assert c2.status_code == 200
        assert c2.json().get("already_paid") is True

    def test_checkout_confirm_404_unknown(self, api_client, base_url):
        r = api_client.post(f"{base_url}/api/checkout/confirm/cs_bogus")
        assert r.status_code == 404


# ----- Return device guard -----
class TestReturnDevice:
    def test_return_device_blocked_when_unpaid(self, api_client, base_url):
        r = api_client.post(f"{base_url}/api/sessions", json={})
        sid = r.json()["id"]
        r = api_client.post(f"{base_url}/api/sessions/{sid}/return-device")
        assert r.status_code == 400

    def test_return_device_404_unknown(self, api_client, base_url):
        r = api_client.post(f"{base_url}/api/sessions/missing/return-device")
        assert r.status_code == 404


# ----- Admin endpoints -----
class TestAdmin:
    def test_admin_sessions_list_no_id_leak(self, api_client, base_url):
        # seed at least one
        api_client.post(f"{base_url}/api/sessions", json={})
        r = api_client.get(f"{base_url}/api/admin/sessions")
        assert r.status_code == 200
        docs = r.json()
        assert isinstance(docs, list) and len(docs) >= 1
        for d in docs:
            assert "_id" not in d
            assert "id" in d

    def test_admin_payments_list_no_id_leak(self, api_client, base_url):
        r = api_client.get(f"{base_url}/api/admin/payments")
        assert r.status_code == 200
        for d in r.json():
            assert "_id" not in d

    def test_admin_stats_fields(self, api_client, base_url):
        r = api_client.get(f"{base_url}/api/admin/stats")
        assert r.status_code == 200
        data = r.json()
        for k in ("total_sessions", "active_sessions", "completed_sessions",
                 "paid_transactions", "refunded_transactions", "station_status"):
            assert k in data
        assert data["station_status"] == "Aktyvi"

    def test_admin_refund_marks_refunded(self, api_client, base_url):
        # Create a session + checkout first
        r = api_client.post(f"{base_url}/api/sessions", json={})
        sid = r.json()["id"]
        api_client.post(
            f"{base_url}/api/checkout/session",
            json={"session_id": sid, "origin_url": base_url},
        )
        r = api_client.post(f"{base_url}/api/admin/refund/{sid}")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["ok"] is True
        assert body["refund_amount_eur"] == 25.0
        assert body["mocked"] is True
        # Verify via GET
        g = api_client.get(f"{base_url}/api/sessions/{sid}").json()
        assert g["payment_status"] == "refunded"
        assert g["status"] == "completed"

    def test_admin_refund_404(self, api_client, base_url):
        r = api_client.post(f"{base_url}/api/admin/refund/missing")
        assert r.status_code == 404


# ----- AI OBD port location (iteration 4) -----
class TestAiObdLocation:
    def test_ai_obd_location_returns_lithuanian_text(self, api_client, base_url):
        r = api_client.post(
            f"{base_url}/api/ai/obd-location",
            json={"brand": "Audi", "model": "A4", "year": "2018"},
            timeout=60,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert "answer" in body
        ans = body["answer"]
        assert isinstance(ans, str) and len(ans) > 20
        # Heuristic: should be Lithuanian-ish (contains at least a couple of common LT words/letters)
        lt_hints = ["jungt", "OBD", "automobil", "vair", "pedal", "vietoj", "rast", "yra"]
        assert any(h.lower() in ans.lower() for h in lt_hints), f"Answer not Lithuanian-looking: {ans}"

    def test_ai_obd_location_bmw(self, api_client, base_url):
        r = api_client.post(
            f"{base_url}/api/ai/obd-location",
            json={"brand": "BMW", "model": "320d", "year": "2020"},
            timeout=60,
        )
        assert r.status_code == 200, r.text
        assert len(r.json().get("answer", "")) > 10

    def test_ai_obd_location_validation_missing_fields(self, api_client, base_url):
        r = api_client.post(f"{base_url}/api/ai/obd-location", json={"brand": "Audi"})
        assert r.status_code == 422


# ----- AI scan errors (iteration 5) -----
class TestAiScanErrors:
    def test_scan_errors_returns_lt_findings_and_persists(self, api_client, base_url):
        r = api_client.post(f"{base_url}/api/sessions", json={})
        sid = r.json()["id"]
        r = api_client.post(
            f"{base_url}/api/ai/scan-errors",
            json={"session_id": sid},
            timeout=90,
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert "findings" in data and isinstance(data["findings"], list)
        assert len(data["findings"]) >= 1
        for f in data["findings"]:
            for k in ("code", "severity", "title", "description", "advice", "clearable"):
                assert k in f, f"missing {k} in finding {f}"
            assert f["severity"] in ("critical", "informational")
            assert isinstance(f["clearable"], bool)
            assert isinstance(f["description"], str) and len(f["description"]) > 5
            # iteration 6: AI advice field
            assert isinstance(f["advice"], str) and len(f["advice"]) > 5
        # Verify persisted into session outcome via GET
        g = api_client.get(f"{base_url}/api/sessions/{sid}").json()
        persisted = g["outcome"]["findings"]
        assert len(persisted) == len(data["findings"])
        assert persisted[0]["code"] == data["findings"][0]["code"]

    def test_scan_errors_deterministic_by_sid(self, api_client, base_url):
        # Same sid yields same pool
        r = api_client.post(f"{base_url}/api/sessions", json={})
        sid = r.json()["id"]
        a = api_client.post(f"{base_url}/api/ai/scan-errors",
                            json={"session_id": sid}, timeout=90).json()
        b = api_client.post(f"{base_url}/api/ai/scan-errors",
                            json={"session_id": sid}, timeout=90).json()
        codes_a = [f["code"] for f in a["findings"]]
        codes_b = [f["code"] for f in b["findings"]]
        assert codes_a == codes_b

    def test_scan_errors_404_unknown_session(self, api_client, base_url):
        r = api_client.post(f"{base_url}/api/ai/scan-errors",
                            json={"session_id": "does-not-exist"})
        assert r.status_code == 404


# ----- Outcome persistence (iteration 5) -----
class TestOutcome:
    def test_outcome_clear_performed_persists(self, api_client, base_url):
        r = api_client.post(f"{base_url}/api/sessions", json={})
        sid = r.json()["id"]
        payload = {
            "outcome": {
                "clear_consent": True,
                "clear_performed": True,
                "cleared_at": "2026-01-15T10:00:00+00:00",
            }
        }
        r = api_client.put(f"{base_url}/api/sessions/{sid}", json=payload)
        assert r.status_code == 200, r.text
        o = r.json()["outcome"]
        assert o["clear_consent"] is True
        assert o["clear_performed"] is True
        assert o["cleared_at"] == "2026-01-15T10:00:00+00:00"
        # GET-verify
        g = api_client.get(f"{base_url}/api/sessions/{sid}").json()["outcome"]
        assert g["clear_consent"] is True
        assert g["clear_performed"] is True

    def test_outcome_report_only(self, api_client, base_url):
        r = api_client.post(f"{base_url}/api/sessions", json={})
        sid = r.json()["id"]
        r = api_client.put(
            f"{base_url}/api/sessions/{sid}",
            json={"outcome": {"clear_consent": False, "clear_performed": False}},
        )
        assert r.status_code == 200
        o = r.json()["outcome"]
        assert o["clear_consent"] is False
        assert o["clear_performed"] is False
        assert o.get("cleared_at") is None
