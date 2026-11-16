"""Build a comprehensive DiaGO source archive (.zip).

Source code files are added as .txt copies for safe download/email
(prevents AV scanners from triggering on .tsx / .py). Binary assets
(fonts, images) are kept in their original format.

Sensitive secrets in .env files are redacted before packaging.
"""
import os, re, zipfile, shutil
from pathlib import Path

ROOT = Path("/app")
OUT_ZIP = ROOT / "backend" / "assets" / "diago_full_source.zip"

# Source extensions that get .txt suffix when added to the zip
TEXT_EXT = {".py", ".ts", ".tsx", ".js", ".jsx", ".json", ".env", ".cfg", ".ini",
            ".toml", ".md", ".yaml", ".yml"}
# Binary kept as-is
BINARY_EXT = {".ttf", ".otf", ".woff", ".woff2", ".png", ".jpg", ".jpeg",
              ".webp", ".gif", ".ico", ".svg"}

EXCLUDE_DIRS = {"node_modules", ".metro-cache", ".ruff_cache", "__pycache__",
                ".git", "venv", ".venv", "dist", "build", ".expo", ".next"}
EXCLUDE_FILES = {".DS_Store", "yarn.lock", "package-lock.json", "diago_source.zip",
                 "diago_full_source.zip", ".gitignore", "expo-env.d.ts",
                 "CACHEDIR.TAG"}
EXCLUDE_PATTERNS = [
    re.compile(r"_preview_.*\.png$"),
    re.compile(r"^\.ruff_cache$"),
]

SECRET_KEYS = [
    "STRIPE_SECRET_KEY", "STRIPE_PUBLISHABLE_KEY", "EMERGENT_LLM_KEY",
    "MONGO_URL", "ADMIN_PASSWORD", "JWT_SECRET", "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY", "GOOGLE_API_KEY", "SENDGRID_API_KEY", "TWILIO_AUTH_TOKEN",
    "TWILIO_ACCOUNT_SID",
]


def redact_env(text: str) -> str:
    out_lines = []
    for line in text.splitlines():
        m = re.match(r'^\s*([A-Z0-9_]+)\s*=\s*(.+)$', line)
        if m and m.group(1) in SECRET_KEYS:
            out_lines.append(f"{m.group(1)}=__REDACTED__")
        else:
            out_lines.append(line)
    return "\n".join(out_lines) + ("\n" if text.endswith("\n") else "")


def is_excluded(p: Path) -> bool:
    parts = set(p.parts)
    if parts & EXCLUDE_DIRS:
        return True
    if p.name in EXCLUDE_FILES:
        return True
    for pat in EXCLUDE_PATTERNS:
        if pat.search(p.name):
            return True
    return False


SUBDIRS = ["backend", "frontend"]


def collect_files():
    files = []
    for sub in SUBDIRS:
        base = ROOT / sub
        for fp in base.rglob("*"):
            if not fp.is_file():
                continue
            if is_excluded(fp):
                continue
            if fp.stat().st_size > 5 * 1024 * 1024:  # > 5MB
                continue
            files.append(fp)
    return files


def build_zip():
    if OUT_ZIP.exists():
        OUT_ZIP.unlink()
    files = collect_files()
    total_text = total_bin = 0
    with zipfile.ZipFile(OUT_ZIP, "w", zipfile.ZIP_DEFLATED, compresslevel=8) as z:
        # Top-level README inside the archive
        readme = (
            "DiaGO – pilnas projekto šaltinio kodas\n"
            "======================================\n\n"
            "Struktūra (kaip ir realiame projekte):\n"
            "  /app/backend/      – FastAPI serveris, PDF generavimas, AI integracija\n"
            "  /app/frontend/     – React Native Expo programėlė (mobilus + web)\n\n"
            "Programos failai (.py / .tsx / .ts / .json / .env) į ZIP pridėti SU\n"
            "papildomu „.txt\" plėtiniu, kad lengvai atsisiunčiamas el. paštu ar archyvu.\n"
            "Norėdami atgaminti veikiantį projektą, tiesiog NUIMKITE „.txt\" plėtinį iš galo.\n\n"
            "Pvz.: server.py.txt → server.py\n\n"
            "Binariniai failai (.ttf šriftai, .png logotipai/paveikslėliai) pridėti\n"
            "originaliais formatais ir nereikalauja perversijos.\n\n"
            "Slapti raktai (.env) ATSARGAUS DĖKLU pakeisti į „__REDACTED__“ – prieš\n"
            "paleidžiant projektą lokaliai, atstatykite savo raktus.\n\n"
            "Sukurta: DiaGO platforma\n"
        )
        z.writestr("diago_source/README.txt", readme)

        for fp in files:
            rel = fp.relative_to(ROOT).as_posix()
            ext = fp.suffix.lower()
            arc = f"diago_source/{rel}"

            if ext in BINARY_EXT or ext not in TEXT_EXT and fp.name not in (".env",):
                # Treat as binary unless explicitly text
                if ext in BINARY_EXT:
                    z.write(fp, arc)
                    total_bin += 1
                    continue
                else:
                    # Unknown ext, skip
                    continue

            # Text file – read, optionally redact, save as .txt
            try:
                text = fp.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            if fp.name == ".env":
                text = redact_env(text)

            z.writestr(arc + ".txt", text)
            total_text += 1

    size_kb = OUT_ZIP.stat().st_size / 1024
    print(f"Wrote {OUT_ZIP}")
    print(f"  Text source files: {total_text}")
    print(f"  Binary assets:     {total_bin}")
    print(f"  Archive size:      {size_kb:.1f} KB")


if __name__ == "__main__":
    build_zip()
