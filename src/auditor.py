
import re
import json
import sys
from pathlib import Path

CIS_RULES = [
    {"id": "CIS-1.1.1", "category": "AAA",
     "title": "Bật xác thực AAA",
     "pattern": r"^aaa new-model",
     "remediation": "aaa new-model"},

    {"id": "CIS-1.2.1", "category": "Password",
     "title": "Dùng enable secret",
     "pattern": r"^enable secret\s+",
     "remediation": "enable secret <pass>"},

    {"id": "CIS-1.2.2", "category": "Password",
     "title": "Mã hóa mật khẩu",
     "pattern": r"^service password-encryption$",
     "remediation": "service password-encryption"},

    {"id": "CIS-1.3.1", "category": "Banner",
     "title": "Banner cảnh báo",
     "pattern": r"^banner (login|motd)",
     "remediation": "banner login ^C ... ^C"},

    {"id": "CIS-2.1.1", "category": "SSH",
     "title": "Dùng SSH v2",
     "pattern": r"^ip ssh version 2$",
     "remediation": "ip ssh version 2"},

    {"id": "CIS-2.1.2", "category": "SSH",
     "title": "Chỉ cho phép SSH",
     "pattern": r"^\s*transport input ssh$",
     "remediation": "transport input ssh"},

    {"id": "CIS-2.1.3", "category": "SSH",
     "title": "Giới hạn IP VTY",
     "pattern": r"^\s*access-class\s+\S+\s+in",
     "remediation": "access-class 10 in"},

    {"id": "CIS-2.1.4", "category": "SSH",
     "title": "Thời gian ngắt VTY",
     "pattern": r"^\s*exec-timeout\s+([1-9]|10)\s+0$",
     "remediation": "exec-timeout 5 0"},

    {"id": "CIS-2.2.1", "category": "Services",
     "title": "Tắt HTTP Server",
     "pattern": r"^no ip http server$",
     "remediation": "no ip http server"},

    {"id": "CIS-2.2.2", "category": "Services",
     "title": "Tắt CDP",
     "pattern": r"^no cdp run$",
     "remediation": "no cdp run"},

    {"id": "CIS-2.2.3", "category": "Services",
     "title": "Chặn Source Route",
     "pattern": r"^no ip source-route$",
     "remediation": "no ip source-route"},

    {"id": "CIS-2.2.4", "category": "Services",
     "title": "Bật TCP Keepalives",
     "pattern": r"^service tcp-keepalives-in$",
     "remediation": "service tcp-keepalives-in"},

    {"id": "CIS-3.1.1", "category": "Logging",
     "title": "Nhãn thời gian log",
     "pattern": r"^service timestamps log datetime msec$",
     "remediation": "service timestamps log datetime msec"},

    {"id": "CIS-3.1.2", "category": "Logging",
     "title": "Máy chủ Syslog",
     "pattern": r"^logging host\s+\d+\.\d+\.\d+\.\d+",
     "remediation": "logging host <ip>"},

    {"id": "CIS-3.1.3", "category": "Logging",
     "title": "Log đăng nhập sai",
     "pattern": r"^login on-failure log$",
     "remediation": "login on-failure log"},

    {"id": "CIS-3.2.1", "category": "NTP",
     "title": "Đồng bộ NTP",
     "pattern": r"^ntp server\s+\d+\.\d+\.\d+\.\d+",
     "remediation": "ntp server <ip>"}
]


def audit_config_text(config_text, filename="uploaded"):
    results = []
    passed = 0

    for rule in CIS_RULES:
        matched = bool(
            re.search(rule["pattern"], config_text, re.MULTILINE)
        )

        if matched:
            passed += 1

        results.append({
            **rule,
            "status": "PASS" if matched else "FAIL"
        })

    score = round((passed / len(CIS_RULES)) * 100, 2)

    return {
        "target_file": filename,
        "total": len(CIS_RULES),
        "passed": passed,
        "failed": len(CIS_RULES) - passed,
        "score": score,
        "details": results
    }


def generate_html_report(data):
    rows = ""

    for item in data["details"]:
        color = "#d4edda" if item["status"] == "PASS" else "#f8d7da"

        rows += f"""
        <tr style="background:{color}">
            <td>{item['id']}</td>
            <td>{item['title']}</td>
            <td>{item['status']}</td>
            <td><code>{item['remediation']}</code></td>
        </tr>
        """

    return f"""
    <html>
    <head>
        <meta charset="UTF-8">
        <title>CIS Benchmark Audit</title>
    </head>
    <body style="font-family:Arial;margin:30px">
        <h1>CIS Benchmark Audit Report</h1>
        <h3>File: {data['target_file']}</h3>
        <h2>Score: {data['score']}%</h2>
        <p>PASS: {data['passed']} / {data['total']}</p>
        <p>FAIL: {data['failed']} / {data['total']}</p>
        <table border="1" cellpadding="10"
               style="border-collapse:collapse;width:100%">
            <tr>
                <th>ID</th>
                <th>Tiêu chí</th>
                <th>Kết quả</th>
                <th>Cách khắc phục</th>
            </tr>
            {rows}
        </table>
    </body>
    </html>
    """


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python auditor.py <config_file>")
        sys.exit(1)

    target = Path(sys.argv[1])

    if not target.is_file():
        print(f"ERROR: Không tìm thấy file {target}")
        sys.exit(1)

    config_text = target.read_text(encoding="utf-8")

    report = audit_config_text(config_text, target.name)

    output_name = target.stem

    json_file = Path(f"audit_report_{output_name}.json")
    html_file = Path(f"audit_report_{output_name}.html")

    json_file.write_text(
        json.dumps(report, indent=4, ensure_ascii=False),
        encoding="utf-8"
    )

    html_file.write_text(
        generate_html_report(report),
        encoding="utf-8"
    )

    print("=" * 45)
    print("CIS BENCHMARK AUDIT")
    print("=" * 45)
    print(f"File: {target.name}")
    print(f"PASS: {report['passed']}/{report['total']}")
    print(f"FAIL: {report['failed']}/{report['total']}")
    print(f"SCORE: {report['score']}%")
    print(f"JSON: {json_file}")
    print(f"HTML: {html_file}")
