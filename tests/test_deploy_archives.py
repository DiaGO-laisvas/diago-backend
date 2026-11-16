# Deployment archive tests: /api/assets/{name} zip downloads + contents (iteration 7)
import io
import re
import zipfile
import pytest
import requests

from conftest import BASE_URL

ARCHIVES = {}


def _get(name):
    if name not in ARCHIVES:
        r = requests.get(f"{BASE_URL}/api/assets/{name}", timeout=60)
        ARCHIVES[name] = r
    return ARCHIVES[name]


def _zip(name):
    r = _get(name)
    assert r.status_code == 200
    return zipfile.ZipFile(io.BytesIO(r.content))


# ---- HTTP level ----
@pytest.mark.parametrize("name,min_kb,max_kb", [
    ("diago_backend.zip", 2500, 5000),
    ("diago_frontend.zip", 1200, 4000),
    ("diago_frontend_web.zip", 400, 1500),
])
def test_archive_http(name, min_kb, max_kb):
    r = _get(name)
    assert r.status_code == 200, r.text[:200]
    assert r.headers["content-type"].startswith("application/zip")
    size_kb = len(r.content) / 1024
    assert min_kb <= size_kb <= max_kb, size_kb
    z = zipfile.ZipFile(io.BytesIO(r.content))
    assert z.testzip() is None  # CRC integrity


def test_asset_404_and_traversal():
    assert requests.get(f"{BASE_URL}/api/assets/does_not_exist.zip").status_code == 404
    r = requests.get(f"{BASE_URL}/api/assets/..%2Fserver.py")
    assert r.status_code in (400, 404)


# ---- backend zip ----
def test_backend_zip_contents():
    names = set(_zip("diago_backend.zip").namelist())
    for f in ["server.py", "pdf_report.py", "requirements.txt",
              "assets/DejaVuSans.ttf", "assets/diago_logo.png",
              ".env", ".env.example", "README.md"]:
        assert f in names, f"missing {f}"


def test_backend_zip_env_redacted():
    z = _zip("diago_backend.zip")
    env = z.read(".env").decode()
    for k in ["MONGO_URL", "STRIPE_API_KEY", "ADMIN_PASSWORD"]:
        m = re.search(rf"^{k}=(.*)$", env, re.M)
        assert m, f"{k} missing in .env"
        assert m.group(1).strip() == "__REDACTED__", f"{k} not redacted"
    ex = z.read(".env.example").decode()
    assert "MONGO_URL=" in ex and "DB_NAME=" in ex


def test_backend_zip_no_nested_archives_or_previews():
    names = _zip("diago_backend.zip").namelist()
    bad = [n for n in names if n.endswith(".zip") or "_preview_" in n or n.endswith(".pyc")]
    assert not bad, bad


# ---- frontend zip ----
def test_frontend_zip_source():
    names = set(_zip("diago_frontend.zip").namelist())
    for f in ["app/index.tsx", "app/vadovas.tsx", "app/active.tsx",
              "components/SupportFab.tsx", "package.json", "yarn.lock"]:
        assert f in names, f"missing {f}"
    assert not any(n.startswith("node_modules/") for n in names)


def test_frontend_zip_dist():
    names = set(_zip("diago_frontend.zip").namelist())
    for f in ["dist/index.html", "dist/vadovas.html", "dist/active.html"]:
        assert f in names, f"missing {f}"
    assert any(re.match(r"dist/_expo/static/js/web/entry-.*\.js$", n) for n in names)


# ---- web zip ----
def test_web_zip_root():
    names = set(_zip("diago_frontend_web.zip").namelist())
    for f in ["index.html", "vadovas.html", "active.html", "chat.html", "admin.html",
              "complete.html", "return.html", "offer.html", "payment-success.html",
              "favicon.ico", "README.md"]:
        assert f in names, f"missing {f}"
    assert any(n.startswith("_expo/static/js/web/") and n.endswith(".js") for n in names)


def _check_html(z, path, names):
    html = z.read(path).decode()
    assert "<html" in html and "<head>" in html
    srcs = re.findall(r'src="([^"]*_expo/static/js/web/[^"]+\.js)"', html)
    assert srcs, "no expo bundle script"
    for s in srcs:
        rel = s.lstrip("/")
        prefix = "dist/" if path.startswith("dist/") else ""
        assert prefix + rel in names, f"bundle {rel} referenced but missing"


def test_index_html_valid_both():
    zw = _zip("diago_frontend_web.zip")
    _check_html(zw, "index.html", set(zw.namelist()))
    zf = _zip("diago_frontend.zip")
    _check_html(zf, "dist/index.html", set(zf.namelist()))


# ---- smoke regression ----
def test_smoke_create_session(api_client):
    r = api_client.post(f"{BASE_URL}/api/sessions", json={"station_id": "KED-01"})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d.get("id") and d.get("station_id") == "KED-01"
    assert "_id" not in d


def test_smoke_config():
    r = requests.get(f"{BASE_URL}/api/config")
    assert r.status_code == 200


# ---- iteration 8: deploy-readiness checks ----
@pytest.mark.parametrize("name", ["diago_backend.zip", "diago_frontend.zip", "diago_frontend_web.zip"])
def test_zip_entries_perms_0644(name):
    # every entry must be a regular file with 0644 perms (nginx-readable after unzip)
    bad = [(i.filename, oct((i.external_attr >> 16) & 0o777)) for i in _zip(name).infolist()
           if (i.external_attr >> 16) & 0o777 != 0o644]
    assert not bad, bad[:10]


def test_web_route_html_titles():
    # all real routes must carry <title>DiaGO</title> (+not-found / _sitemap may be empty)
    z = _zip("diago_frontend_web.zip")
    for h in ["index", "vadovas", "active", "chat", "admin", "complete", "return",
              "offer", "payment-success"]:
        html = z.read(f"{h}.html").decode()
        assert re.search(r"<title[^>]*>DiaGO</title>", html), f"{h}.html title missing"


def test_web_bundle_no_preview_url_and_relative_api():
    # bundle must not bake the preview emergentagent URL; API must be same-origin /api
    z = _zip("diago_frontend_web.zip")
    for n in z.namelist():
        if n.endswith((".js", ".html", ".json", ".md")):
            assert b"emergentagent" not in z.read(n), f"preview URL baked into {n}"
    js = [n for n in z.namelist() if n.startswith("_expo/static/js/web/") and n.endswith(".js")]
    assert len(js) == 1
    assert b"fetch(`/api${" in z.read(js[0])


def test_frontend_zip_dist_no_preview_url():
    # dist/ inside source zip must also be the relative-/api build
    z = _zip("diago_frontend.zip")
    for n in z.namelist():
        if n.startswith("dist/") and n.endswith((".js", ".html")):
            assert b"emergentagent" not in z.read(n), n


def test_web_readme_accurate():
    z = _zip("diago_frontend_web.zip")
    readme = z.read("README.md").decode()
    assert "_expo/static/css" not in readme
    assert "_expo/static/js/" in readme and "assets/node_modules" in readme
    assert "try_files" in readme and "location /api/" in readme


def test_web_assets_node_modules_included_and_referenced_exist():
    # every /assets/... path referenced from the bundle must exist in the zip
    z = _zip("diago_frontend_web.zip")
    names = set(z.namelist())
    nm = [n for n in names if n.startswith("assets/node_modules/")]
    assert len(nm) >= 18, len(nm)
    js = next(n for n in names if n.startswith("_expo/static/js/web/") and n.endswith(".js"))
    refs = set(re.findall(rb'"/(assets/[^"]+)"', z.read(js)))
    missing = [r.decode() for r in refs if r.decode() not in names]
    assert not missing, missing
    zf = set(_zip("diago_frontend.zip").namelist())
    assert len([n for n in zf if n.startswith("dist/assets/node_modules/")]) >= 18


def test_backend_zip_no_cache_dirs():
    # nested cache dirs (.pytest_cache, __pycache__) should not ship
    names = _zip("diago_backend.zip").namelist()
    bad = [n for n in names if "/.pytest_cache/" in n or "/__pycache__/" in n
           or n.startswith((".pytest_cache/", "__pycache__/"))]
    assert not bad, bad
