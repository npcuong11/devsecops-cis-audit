
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pathlib import Path

from auditor import audit_config_text, generate_html_report

app = FastAPI(
    title="CIS Benchmark Audit API",
    description="Cisco IOS Security Configuration Auditor",
    version="1.0.0"
)

# Docker Compose mount cấu hình vào /configs
CONFIG_DIR = Path("/configs")


def get_report(mode: str):
    if mode not in ["vulnerable", "hardened"]:
        raise HTTPException(
            status_code=400,
            detail="Mode phải là vulnerable hoặc hardened"
        )

    filename = f"router_{mode}.cfg"
    file_path = CONFIG_DIR / filename

    if not file_path.is_file():
        raise HTTPException(
            status_code=404,
            detail=f"Không tìm thấy file {filename}"
        )

    config_text = file_path.read_text(encoding="utf-8")

    return audit_config_text(config_text, filename)


@app.get("/")
def home():
    return {
        "message": "CIS Benchmark Audit API",
        "version": "1.0.0",
        "endpoints": [
            "/report/hardened",
            "/report/vulnerable",
            "/report/hardened/json",
            "/report/vulnerable/json",
            "/docs"
        ]
    }


@app.get("/report/{mode}", response_class=HTMLResponse)
def view_html_report(mode: str):
    report = get_report(mode)
    return generate_html_report(report)


@app.get("/report/{mode}/json")
def view_json_report(mode: str):
    report = get_report(mode)
    return JSONResponse(content=report)
