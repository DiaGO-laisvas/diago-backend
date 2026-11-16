"""Build two SEPARATE deployment-ready DiaGO archives:
  • /app/backend/assets/diago_backend.zip  — FastAPI + Python
  • /app/backend/assets/diago_frontend.zip — Expo React Native

Files keep their ORIGINAL extensions (no .txt suffix) so you can unzip
straight into GitHub or a server and run `pip install -r requirements.txt`
or `yarn install && yarn start` without any renaming.

.env secrets are redacted (replaced with __REDACTED__) so it is safe to
push to GitHub.  A `.env.example` with matching keys is included for
onboarding.
"""
from __future__ import annotations
import os, re, zipfile, shutil, time
from pathlib import Path

ROOT = Path("/app")
OUT_DIR = ROOT / "backend" / "assets"
OUT_DIR.mkdir(parents=True, exist_ok=True)

BACKEND_ZIP = OUT_DIR / "diago_backend.zip"
FRONTEND_ZIP = OUT_DIR / "diago_frontend.zip"
WEB_BUILD_ZIP = OUT_DIR / "diago_frontend_web.zip"

# --- Exclusions ------------------------------------------------------------
EXCLUDE_DIRS = {
    "node_modules", ".metro-cache", ".ruff_cache", "__pycache__",
    ".git", "venv", ".venv", "build", ".expo", ".next",
    ".cache", ".idea", ".vscode", "coverage", ".pytest_cache",
    "test_reports",
    # Note: we KEEP "dist" so frontend zip includes the pre-rendered web build
}
# Patterns that match generated files inside kept directories (backend/assets)
EXCLUDE_FILES = {
    ".DS_Store", "diago_source.zip", "diago_full_source.zip",
    "diago_backend.zip", "diago_frontend.zip", "diago_frontend_web.zip",
    "CACHEDIR.TAG",
    "expo-env.d.ts", "README.md",  # we write our own README.md
    "package-lock.json",  # project uses yarn (yarn.lock)
}
CACHE_DIRS = {
    "__pycache__", ".pytest_cache", ".ruff_cache", ".metro-cache", ".cache",
}
# Environment-specific keys of the Emergent preview — dropped from shipped .env
ENV_DROP_KEYS = {
    "EXPO_PACKAGER_PROXY_URL", "EXPO_PACKAGER_HOSTNAME",
    "EXPO_TUNNEL_SUBDOMAIN", "METRO_CACHE_ROOT", "EXPO_USE_FAST_RESOLVER",
}
EXCLUDE_PATTERNS = [
    re.compile(r"_preview_.*\.png$"),     # generated PDF preview screenshots
    re.compile(r"\.pyc$"),
    re.compile(r"\.log$"),
    re.compile(r"\.pdf$"),                # generated PDF reports
]

SECRET_KEYS = [
    "STRIPE_SECRET_KEY", "STRIPE_PUBLISHABLE_KEY", "STRIPE_API_KEY",
    "EMERGENT_LLM_KEY", "MONGO_URL", "ADMIN_PASSWORD", "JWT_SECRET",
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY",
    "SENDGRID_API_KEY", "TWILIO_AUTH_TOKEN", "TWILIO_ACCOUNT_SID",
]


def write_entry(z: zipfile.ZipFile, arc: str, data: str | bytes | None = None,
                src: Path | None = None) -> None:
    """Write a zip entry with standard permissions (0644 files)."""
    zi = zipfile.ZipInfo.from_file(src, arc) if src else zipfile.ZipInfo(arc, time.localtime()[:6])
    zi.compress_type = zipfile.ZIP_DEFLATED
    zi.external_attr = (0o100644 << 16)
    z.writestr(zi, src.read_bytes() if src else data)


def is_excluded(p: Path, root: Path) -> bool:
    try:
        rel = p.relative_to(root)
    except ValueError:
        return True
    rel_parts = rel.parts
    # Only exclude EXCLUDE_DIRS when they appear at the TOP LEVEL of the
    # source tree (not deep inside dist/assets/node_modules/... which Expo
    # exports as part of the web build).
    if rel_parts and rel_parts[0] in EXCLUDE_DIRS:
        return True
    # Cache folders are excluded at ANY depth.
    if any(part in CACHE_DIRS for part in rel_parts[:-1]):
        return True
    if p.name in EXCLUDE_FILES:
        return True
    for pat in EXCLUDE_PATTERNS:
        if pat.search(p.name):
            return True
    return False


def redact_env(text: str) -> tuple[str, list[str]]:
    """Return (redacted_text, list_of_keys_seen)."""
    out_lines, keys = [], []
    for line in text.splitlines():
        m = re.match(r'^\s*([A-Z0-9_]+)\s*=\s*(.+)$', line)
        if m:
            keys.append(m.group(1))
            if m.group(1) in SECRET_KEYS:
                out_lines.append(f"{m.group(1)}=__REDACTED__")
            elif m.group(1) in ENV_DROP_KEYS:
                continue
            elif m.group(1) == "EXPO_PUBLIC_BACKEND_URL":
                out_lines.append("EXPO_PUBLIC_BACKEND_URL=")
            else:
                out_lines.append(line)
        else:
            out_lines.append(line)
    return "\n".join(out_lines) + ("\n" if text.endswith("\n") else ""), keys


def env_example(keys: list[str]) -> str:
    """Build a .env.example with blank values."""
    header = (
        "# DiaGO environment variables template\n"
        "# Copy this file to .env and fill in the real values.\n\n"
    )
    seen, lines = set(), []
    for k in keys:
        if k in seen or k in ENV_DROP_KEYS:
            continue
        seen.add(k)
        if k in SECRET_KEYS:
            lines.append(f"{k}=your-{k.lower().replace('_','-')}-here")
        else:
            lines.append(f"{k}=")
    return header + "\n".join(lines) + "\n"


# --- Archive builder -------------------------------------------------------
def build_archive(src_root: Path, zip_path: Path, extra_files: dict[str, str]):
    if zip_path.exists():
        zip_path.unlink()

    added_text = added_bin = 0
    env_keys: list[str] = []

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=8) as z:
        for fp in sorted(src_root.rglob("*")):
            if not fp.is_file():
                continue
            if is_excluded(fp, src_root):
                continue
            # Skip huge files (safety)
            try:
                if fp.stat().st_size > 10 * 1024 * 1024:
                    continue
            except Exception:
                continue

            rel = fp.relative_to(src_root).as_posix()
            arc = rel  # Original path, no prefix — keeps repo clean

            if fp.name == ".env":
                try:
                    text = fp.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue
                red, keys = redact_env(text)
                env_keys.extend(keys)
                write_entry(z, arc, red)
                added_text += 1
                continue

            # Binary vs text: just write as-is; zipfile handles both.
            try:
                write_entry(z, arc, src=fp)
            except Exception:
                continue
            # Count rough category
            if fp.suffix.lower() in {".py", ".tsx", ".ts", ".js", ".jsx",
                                      ".json", ".cfg", ".ini", ".toml",
                                      ".md", ".yaml", ".yml", ".env",
                                      ".txt", ".html", ".css"}:
                added_text += 1
            else:
                added_bin += 1

        # Extra generated files (.env.example, README)
        for name, content in extra_files.items():
            write_entry(z, name, content)

        # Generate .env.example from collected keys (if any)
        if env_keys:
            write_entry(z, ".env.example", env_example(env_keys))

    size_kb = zip_path.stat().st_size / 1024
    return {
        "path": zip_path,
        "text_files": added_text,
        "binary_files": added_bin,
        "size_kb": size_kb,
    }


# --- Readmes ---------------------------------------------------------------
BACKEND_README = """# DiaGO Backend (FastAPI + MongoDB)

Diagnostikos paslaugų backend'as su AI analize, Stripe mokėjimais ir
PDF ataskaitų generavimu.

## Paleidimas lokaliai

```bash
python -m venv venv
source venv/bin/activate      # arba: venv\\Scripts\\activate (Windows)
pip install -r requirements.txt

cp .env.example .env          # ir įrašykite savo API raktus
uvicorn server:app --host 0.0.0.0 --port 8001 --reload
```

Reikalingi paslaugų raktai (į .env):
- `MONGO_URL` – jūsų MongoDB connection string
- `STRIPE_SECRET_KEY` + `STRIPE_PUBLISHABLE_KEY` – iš https://dashboard.stripe.com
- `EMERGENT_LLM_KEY` – AI integracijai (Claude / Gemini / OpenAI)
- `ADMIN_PASSWORD` – admin panelės slaptažodis

## Struktūra

- `server.py` – pagrindinis FastAPI entry point, visi /api/* maršrutai
- `pdf_report.py` – individualizuotas PDF ataskaitos generatorius
- `build_source_archive.py` / `build_deploy_archives.py` – source eksportas
- `tests/` – backend testai

## API maršrutai

Visi po prefiksu `/api/*` (kad atskirti nuo frontend'o). Pagrindiniai:
- `POST /api/sessions` – nauja diagnostikos sesija
- `POST /api/ai/scan-errors` – OBD2 klaidų skenavimas
- `GET /api/reports/{sid}.pdf` – PDF ataskaita
- `POST /api/support/chat` – AI pagalbos chat'as
- `POST /api/checkout/session` – Stripe mokėjimas
"""

FRONTEND_README = """# DiaGO Frontend (Expo React Native)

Mobilus + web klientas DiaGO savitarnos diagnostikos stotelei.

## Paleidimas lokaliai

```bash
yarn install
cp .env.example .env          # įrašykite EXPO_PUBLIC_BACKEND_URL (arba palikite tuščią, jei /api tame pačiame domene)
yarn start                    # arba: yarn android / yarn ios / yarn web
```

## Reikalingos aplinkos reikšmės (.env)

- `EXPO_PUBLIC_BACKEND_URL` – backend'o viešas URL (pvz. https://api.diago.lt).
  Tuščia reikšmė = užklausos į tą patį domeną per `/api/...`.

## Pagrindinės rinkmenos

- `app/index.tsx` – pradinis ekranas
- `app/chat.tsx` – pokalbio pradžia
- `app/active.tsx` – aktyvi diagnostika (OBD2, skenavimas, ataskaita)
- `app/admin.tsx` – admin panelė
- `app/vadovas.tsx` – vartotojo vadovas /vadovas
- `components/` – perpanaudojami UI komponentai
- `components/SupportFab.tsx` – 24/7 pagalbos modal'is (Kontaktai, Vadovas,
  AI pokalbis)
- `lib/api.ts` – backend'o API klientas
- `constants/theme.ts` – dizaino spalvos ir tipografija

## Build / Deploy

Projektas – standartinis Expo SDK. Deploy'ui į stotelę ar web'ą:
- Web: `expo export --platform web` → statinis build'as į `dist/`
- iOS/Android: `eas build` (reikia EAS paskyros)
"""


WEB_BUILD_README = """# DiaGO Web Build (static HTML + JS)

Tai yra JAU SUKOMPILIUOTAS Expo web build'as — galutinis pre-rendered statinis
tinklapis, kurį galite įkelti TIESIOGIAI į serverį (pvz. baobabas.serveriai.lt)
po Nginx, Apache ar bet kokiu statiniu failų hosting'u.

## Struktūra

- `index.html` – pradinis puslapis
- `active.html`, `chat.html`, `admin.html`, `vadovas.html`, ... – visi maršrutai
- `_expo/static/js/` – kompiliuoto JavaScript bundle'as (stiliai įkompiliuoti į JS)
- `assets/` – paveikslėliai (įskaitant `assets/node_modules/...` – NEtrinkite)
- `favicon.ico`

## Deploy'imas į serverį

```bash
# 1) Išarchyvuokite į Nginx document root
unzip diago_frontend_web.zip -d /var/www/diago

# 2) Nginx konfigūracijoje (/etc/nginx/sites-available/diago):
server {
    listen 80;
    server_name diago.lt www.diago.lt;
    root /var/www/diago;
    index index.html;

    # SPA routing — jei URL nerastas kaip failas, grąžinti index.html
    location / {
        try_files $uri $uri.html $uri/ /index.html;
    }

    # Backend API reverse proxy
    location /api/ {
        proxy_pass http://127.0.0.1:8001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## SVARBU – backend URL

Šis web build'as sukompiliuotas su TUŠČIA `EXPO_PUBLIC_BACKEND_URL`
reikšme, t.y. visos užklausos eina į tą patį domeną per `/api/...`
(todėl būtina aukščiau nurodyta Nginx `location /api/` taisyklė).
Jei backend'as yra kitame domene, perbuildinkite iš `diago_frontend.zip`:

```bash
unzip diago_frontend.zip -d diago-source
cd diago-source
echo 'EXPO_PUBLIC_BACKEND_URL=https://api.diago.lt' > .env
yarn install
yarn expo export --platform web
# Statinis build'as atsiras `dist/` – įkelkite jį į serverį.
```
"""


def build_web_build_archive() -> dict:
    """Package the already-exported `dist/` folder as a standalone zip."""
    dist_dir = ROOT / "frontend" / "dist"
    if not dist_dir.exists():
        print(f"✗ Nėra {dist_dir}. Pirmiausia paleiskite: yarn expo export --platform web")
        return {}

    if WEB_BUILD_ZIP.exists():
        WEB_BUILD_ZIP.unlink()

    total_files = 0
    with zipfile.ZipFile(WEB_BUILD_ZIP, "w", zipfile.ZIP_DEFLATED, compresslevel=8) as z:
        for fp in sorted(dist_dir.rglob("*")):
            if not fp.is_file():
                continue
            arc = fp.relative_to(dist_dir).as_posix()
            write_entry(z, arc, src=fp)
            total_files += 1
        write_entry(z, "README.md", WEB_BUILD_README)

    size_kb = WEB_BUILD_ZIP.stat().st_size / 1024
    return {
        "path": WEB_BUILD_ZIP,
        "files": total_files,
        "size_kb": size_kb,
    }


def main():
    print("Building DiaGO deployment archives...\n")

    # Backend archive
    backend_src = ROOT / "backend"
    b = build_archive(backend_src, BACKEND_ZIP, {
        "README.md": BACKEND_README,
    })
    print(f"✓ Backend:  {b['path'].name}")
    print(f"    {b['text_files']} text + {b['binary_files']} binary files")
    print(f"    {b['size_kb']:.1f} KB\n")

    # Frontend archive
    frontend_src = ROOT / "frontend"
    f = build_archive(frontend_src, FRONTEND_ZIP, {
        "README.md": FRONTEND_README,
    })
    print(f"✓ Frontend: {f['path'].name}")
    print(f"    {f['text_files']} text + {f['binary_files']} binary files")
    print(f"    {f['size_kb']:.1f} KB\n")

    # Web build archive (pre-rendered static HTML+JS)
    w = build_web_build_archive()
    if w:
        print(f"✓ Web build: {w['path'].name}")
        print(f"    {w['files']} files")
        print(f"    {w['size_kb']:.1f} KB\n")

    print("Download URLs (via backend):")
    print(f"  /api/assets/{BACKEND_ZIP.name}")
    print(f"  /api/assets/{FRONTEND_ZIP.name}")
    if w:
        print(f"  /api/assets/{WEB_BUILD_ZIP.name}")


if __name__ == "__main__":
    main()
