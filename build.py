from pathlib import Path
import shutil


ROOT = Path(__file__).resolve().parent
PUBLIC = ROOT / "public"
PUBLIC.mkdir(exist_ok=True)

for name in ("index.html", "app.css", "app.js"):
    shutil.copy2(ROOT / name, PUBLIC / name)

shutil.copytree(ROOT / "assets", PUBLIC / "assets", dirs_exist_ok=True)
