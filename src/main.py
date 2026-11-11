from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pathlib import Path
from auditor import audit_config_text, generate_html_report

app = FastAPI(title="CIS Auditor API")
CONFIG_DIR = Path("../configs")

@app.get("/report/{mode}", response_class=HTMLResponse)
def view_html_report(mode: str = "hardened"):
    filename = "router_vulnerable.cfg" if mode == "vulnerable" else "router_hardened.cfg"
    file_path = CONFIG_DIR / filename
    report = audit_config_text(file_path.read_text(encoding="utf-8"), filename)
    return generate_html_report(report)