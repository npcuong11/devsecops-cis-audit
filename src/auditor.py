import re, json, sys
from pathlib import Path

CIS_RULES = [
    {"id": "CIS-1.1.1", "category": "AAA", "title": "Bật xác thực AAA", "pattern": r"^aaa new-model", "remediation": "aaa new-model"},
    {"id": "CIS-1.2.1", "category": "Password", "title": "Dùng enable secret", "pattern": r"^enable secret\s+", "remediation": "enable secret <pass>"},
    {"id": "CIS-1.2.2", "category": "Password", "title": "Mã hóa mật khẩu", "pattern": r"^service password-encryption", "remediation": "service password-encryption"},
    {"id": "CIS-1.3.1", "category": "Banner", "title": "Banner cảnh báo", "pattern": r"^banner (login|motd)", "remediation": "banner login ^C ... ^C"},
    {"id": "CIS-2.1.1", "category": "SSH", "title": "Dùng SSH v2", "pattern": r"^ip ssh version 2", "remediation": "ip ssh version 2"},
    {"id": "CIS-2.1.2", "category": "SSH", "title": "Chỉ cho phép SSH", "pattern": r"^\s*transport input ssh$", "remediation": "transport input ssh"},
    {"id": "CIS-2.1.3", "category": "SSH", "title": "Giới hạn IP VTY", "pattern": r"^\s*access-class\s+\S+\s+in", "remediation": "access-class 10 in"},
    {"id": "CIS-2.1.4", "category": "SSH", "title": "Thời gian ngắt VTY", "pattern": r"^\s*exec-timeout\s+([1-9]|10)\s+0", "remediation": "exec-timeout 5 0"},
    {"id": "CIS-2.2.1", "category": "Services", "title": "Tắt HTTP Server", "pattern": r"^no ip http server", "remediation": "no ip http server"},
    {"id": "CIS-2.2.2", "category": "Services", "title": "Tắt CDP", "pattern": r"^no cdp run", "remediation": "no cdp run"},
    {"id": "CIS-2.2.3", "category": "Services", "title": "Chặn Source Route", "pattern": r"^no ip source-route", "remediation": "no ip source-route"},
    {"id": "CIS-2.2.4", "category": "Services", "title": "Bật TCP Keepalives", "pattern": r"^service tcp-keepalives-in", "remediation": "service tcp-keepalives-in"},
    {"id": "CIS-3.1.1", "category": "Logging", "title": "Nhãn thời gian log", "pattern": r"^service timestamps log datetime msec", "remediation": "service timestamps log datetime msec"},
    {"id": "CIS-3.1.2", "category": "Logging", "title": "Máy chủ Syslog", "pattern": r"^logging host\s+\d+\.\d+\.\d+\.\d+", "remediation": "logging host <ip>"},
    {"id": "CIS-3.1.3", "category": "Logging", "title": "Log đăng nhập sai", "pattern": r"^login on-failure log", "remediation": "login on-failure log"},
    {"id": "CIS-3.2.1", "category": "NTP", "title": "Đồng bộ NTP", "pattern": r"^ntp server\s+\d+\.\d+\.\d+\.\d+", "remediation": "ntp server <ip>"}
]

def audit_config_text(config_text: str, filename: str = "uploaded"):
    results = []
    passed = 0
    for rule in CIS_RULES:
        matched = bool(re.search(rule["pattern"], config_text, re.MULTILINE))
        if matched: passed += 1
        results.append({**rule, "status": "PASS" if matched else "FAIL"})
    score = round((passed / len(CIS_RULES)) * 100, 2)
    return {"target_file": filename, "total": len(CIS_RULES), "passed": passed, "score": score, "details": results}

def generate_html_report(data: dict) -> str:
    rows = "".join([f"<tr style='background:{'#d4edda' if i['status']=='PASS' else '#f8d7da'}'><td>{i['id']}</td><td>{i['title']}</td><td>{'✅ PASS' if i['status']=='PASS' else '❌ FAIL'}</td><td><code>{i['remediation']}</code></td></tr>" for i in data['details']])
    return f"<html><body style='font-family:Arial; margin:20px'><h2>Báo Cáo CIS Benchmark</h2><h3>Điểm: {data['score']}% ({data['passed']}/{data['total']})</h3><table border='1' cellpadding='8' style='border-collapse:collapse; width:100%'><tr><th>Mã</th><th>Tiêu chí</th><th>Kết quả</th><th>Cách vá</th></tr>{rows}</table></body></html>"

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "../configs/router_hardened.cfg"
    text = Path(target).read_text(encoding="utf-8")
    report = audit_config_text(text, target)
    Path("audit_report.html").write_text(generate_html_report(report), encoding="utf-8")
    print(f"Đã chấm điểm: {report['score']}%")