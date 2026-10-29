#!/usr/bin/env python3
"""Builds test-results/report.html from the JUnit XML reports and the E2E JSON."""

import html
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "test-results"

AREAS = {
    "TotpTest": "TOTP 2차 인증 (RFC 6238 / RFC 4648)",
    "PasswordAndMaskingTest": "비밀번호 해시 · 마스킹",
    "EncryptionTest": "DB 컬럼 암호화 · 키 관리",
    "JwtTest": "SSO 토큰 (JWT RS256) · 공격 차단",
}

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1c2230;--muted:#5e6878;--line:#e2e5ea;--ok:#17794a;--ok-bg:#e3f3e9;
--bad:#b3261e;--bad-bg:#fcebea;--accent:#2456c4}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#101317;--card:#181c22;--text:#e4e7ec;
--muted:#97a0ad;--line:#29303a;--ok:#4cc38a;--ok-bg:#12301f;--bad:#ff7b72;--bad-bg:#3a1a18;--accent:#7aa2f7}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.55 -apple-system,"Segoe UI","Malgun Gothic",sans-serif}
main{max-width:1000px;margin:0 auto;padding:28px 16px 60px}h1{font-size:24px;margin:0 0 4px}
h2{font-size:18px;margin:30px 0 10px}h3{font-size:15px;margin:20px 0 8px}.sub{color:var(--muted);margin:0 0 18px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.tile .v{font-size:26px;font-weight:700}.tile .k{color:var(--muted);font-size:13px}.ok{color:var(--ok)}.bad{color:var(--bad)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:8px 12px;
border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-size:12px}
tr:last-child td{border-bottom:none}.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;
font-weight:600}.badge.pass{background:var(--ok-bg);color:var(--ok)}.badge.fail{background:var(--bad-bg);color:var(--bad)}
.d{color:var(--muted);font-size:12.5px;word-break:break-all}.num{text-align:right;white-space:nowrap}
"""


def esc(s):
    return html.escape(str(s))


def unit_results():
    suites = []
    for xml in sorted((ROOT / "core" / "target" / "surefire-reports").glob("TEST-*.xml")):
        root = ET.parse(xml).getroot()
        cls = xml.stem.split(".")[-1]
        cases = []
        for tc in root.iter("testcase"):
            fail = tc.find("failure") if tc.find("failure") is not None else tc.find("error")
            cases.append({"name": tc.get("name"), "ms": float(tc.get("time", 0)) * 1000,
                          "ok": fail is None, "msg": "" if fail is None else fail.get("message", "")})
        suites.append((AREAS.get(cls, cls), cases))
    return suites


def badge(ok):
    return "<span class='badge pass'>PASS</span>" if ok else "<span class='badge fail'>FAIL</span>"


def main():
    suites = unit_results()
    unit_total = sum(len(c) for _, c in suites)
    unit_ok = sum(1 for _, cs in suites for c in cs if c["ok"])
    e2e = json.loads((OUT / "e2e.json").read_text(encoding="utf-8")) if (OUT / "e2e.json").exists() else None

    p = ["<!doctype html><html lang='ko'><head><meta charset='utf-8'>",
         "<meta name='viewport' content='width=device-width,initial-scale=1'><title>TrustGate Test Report</title>",
         f"<style>{CSS}</style></head><body><main>",
         "<h1>TrustGate 테스트 결과</h1>",
         "<p class='sub'>단위 테스트(JUnit 5)와, Tomcat 10.1 + Oracle Database Free 위에서 실제 HTTP로 돌린 End-to-End 테스트</p>",
         "<div class='tiles'>",
         f"<div class='tile'><div class='v {'ok' if unit_ok == unit_total else 'bad'}'>{unit_ok} / {unit_total}</div>"
         "<div class='k'>단위 테스트 통과</div></div>"]
    if e2e:
        p.append(f"<div class='tile'><div class='v {'ok' if e2e['passed'] == e2e['total'] else 'bad'}'>"
                 f"{e2e['passed']} / {e2e['total']}</div><div class='k'>E2E 검증 항목 통과</div></div>")
        attacks = sum(1 for r in e2e["results"] if r.get("ok") and any(w in r["name"] for w in
                      ("거부", "차단", "방지", "방어", "잠금", "끊기지")))
        p.append(f"<div class='tile'><div class='v'>{attacks}</div><div class='k'>공격·오용 시나리오 차단 확인</div></div>")
    p.append("</div>")

    if e2e:
        p.append("<h2>1. End-to-End (실제 서버, 실제 HTTP)</h2>")
        p.append("<p class='sub'>브라우저처럼 쿠키·리다이렉트·CSRF 토큰을 처리하는 Python 클라이언트로 전체 흐름을 실행했습니다. "
                 "OTP 코드는 서버와 별개로 Python에서 계산했습니다.</p>")
        open_card = False
        for r in e2e["results"]:
            if "section" in r:
                if open_card:
                    p.append("</table></div>")
                p.append(f"<h3>{esc(r['section'])}</h3><div class='card'><table>"
                         "<tr><th style='width:70px'>결과</th><th>확인 내용</th></tr>")
                open_card = True
                continue
            detail = f"<div class='d'>{esc(r['detail'])}</div>" if r.get("detail") else ""
            p.append(f"<tr><td>{badge(r['ok'])}</td><td>{esc(r['name'])}{detail}</td></tr>")
        if open_card:
            p.append("</table></div>")

    p.append("<h2>2. 단위 테스트 (JUnit 5)</h2>")
    for area, cases in suites:
        ok = sum(1 for c in cases if c["ok"])
        p.append(f"<h3>{esc(area)} <span class='badge {'pass' if ok == len(cases) else 'fail'}'>{ok}/{len(cases)}</span></h3>")
        p.append("<div class='card'><table><tr><th style='width:70px'>결과</th><th>테스트</th><th class='num'>시간</th></tr>")
        for c in cases:
            msg = f"<div class='d'>{esc(c['msg'])}</div>" if c["msg"] else ""
            p.append(f"<tr><td>{badge(c['ok'])}</td><td>{esc(c['name'])}{msg}</td>"
                     f"<td class='num'>{c['ms']:.0f} ms</td></tr>")
        p.append("</table></div>")
    p.append("</main></body></html>")

    OUT.mkdir(exist_ok=True)
    (OUT / "report.html").write_text("".join(p), encoding="utf-8")
    print(f"wrote {OUT / 'report.html'}: unit {unit_ok}/{unit_total}"
          + (f", e2e {e2e['passed']}/{e2e['total']}" if e2e else ""))
    return 0 if unit_ok == unit_total and (not e2e or e2e["passed"] == e2e["total"]) else 1


if __name__ == "__main__":
    sys.exit(main())
