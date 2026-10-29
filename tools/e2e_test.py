#!/usr/bin/env python3
"""End-to-end test against a running TrustGate (docker compose up).

Drives the real HTTP flow like a browser (cookies, redirects, CSRF tokens) and checks both
the normal path and attack cases. TOTP codes are computed here with an independent
implementation, which also proves compatibility with standard authenticator apps.

usage: e2e_test.py [BASE_URL] [OUT_JSON]
"""

import base64
import hashlib
import hmac
import html as htmlmod
import http.cookiejar
import json
import pathlib
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"

# On Windows "localhost" resolves to ::1 first, and the container port is bound to IPv4 only,
# which costs ~2 s per request. Try IPv4 first; URLs and cookies still use "localhost".
_getaddrinfo = socket.getaddrinfo
socket.getaddrinfo = lambda *a, **k: sorted(_getaddrinfo(*a, **k), key=lambda r: r[0] != socket.AF_INET)
OUT = sys.argv[2] if len(sys.argv) > 2 else None
PORTAL_SECRET = "portal-demo-secret"

results = []


def check(name, ok, detail=""):
    results.append({"name": name, "ok": bool(ok), "detail": detail})
    mark = "\033[32mPASS\033[0m" if ok else "\033[31mFAIL\033[0m"
    print(f"  [{mark}] {name}" + (f"  ({detail})" if detail else ""), flush=True)


def section(title):
    print(f"\n\033[1;36m== {title} ==\033[0m", flush=True)
    results.append({"section": title})


# --- TOTP (RFC 6238), independent of the Java implementation ------------------------------

def totp(secret_b32, step=None):
    key = base64.b32decode(secret_b32.replace(" ", "") + "=" * (-len(secret_b32.replace(" ", "")) % 8))
    step = int(time.time()) // 30 if step is None else step
    h = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000).zfill(6)


# --- a tiny browser -----------------------------------------------------------------------

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Browser:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect)

    def request(self, method, url, data=None, headers=None, follow=True):
        """Returns (status, final_url, body, chain, headers). chain lists every URL visited."""
        chain = []
        url = urllib.parse.urljoin(BASE, url)
        for _ in range(15):
            chain.append(url)
            body = urllib.parse.urlencode(data).encode() if data is not None else None
            req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
            try:
                res = self.opener.open(req, timeout=10)
                status, hdrs, text = res.status, res.headers, res.read().decode("utf-8", "replace")
                text = htmlmod.unescape(text)
            except urllib.error.HTTPError as e:
                status, hdrs, text = e.code, e.headers, e.read().decode("utf-8", "replace")
                text = htmlmod.unescape(text)
            if follow and status in (301, 302, 303) and hdrs.get("Location"):
                url = urllib.parse.urljoin(url, hdrs["Location"])
                method, data = "GET", None
                continue
            return status, url, text, chain, hdrs
        raise RuntimeError("too many redirects")

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, data, **kw):
        return self.request("POST", url, data=data, **kw)


def csrf(html):
    m = re.search(r'name="csrf" value="([^"]+)"', html)
    return m.group(1) if m else ""


def full_login(b, start_url, username, password, secret=None):
    """Password + OTP. Returns (final status, url, html, chain, secret)."""
    s, url, html, chain, _ = b.get(start_url)
    if "/idp/login" not in url:
        return s, url, html, chain, secret
    s, url, html, chain2, _ = b.post("/idp/login", {"csrf": csrf(html), "username": username, "password": password})
    chain += chain2
    if url.endswith("/otp/enroll"):
        secret = re.search(r'class="secret">([A-Z2-7 ]+)<', html).group(1)
        code = totp(secret)
        s, url, html, chain3, _ = b.post("/idp/otp/enroll", {"csrf": csrf(html), "code": code})
        return s, url, html, chain + chain3, secret
    if url.endswith("/otp"):
        if secret:
            code = totp(secret, int(time.time()) // 30 + 1)  # next step: never used before
        else:
            code = re.search(r"지금 유효한 코드: <code>(\d{6})</code>", html).group(1)
        s, url, html, chain3, _ = b.post("/idp/otp", {"csrf": csrf(html), "code": code})
        return s, url, html, chain + chain3, secret
    return s, url, html, chain, secret


def main():
    run_id = str(int(time.time()))[-6:]
    username = f"e2e{run_id}"
    password = "E2e!pass" + run_id
    rrn = "990101-1" + run_id  # made-up number, unique per run

    # ------------------------------------------------------------------ setup via admin
    section("준비: 관리자로 테스트 사용자 생성 (개인정보 암호화 저장)")
    admin = Browser()
    s, url, html, chain, _ = full_login(admin, "/idp/admin", "admin", "Admin!2345")
    s, url, html, _, _ = admin.get("/idp/admin")
    check("관리자 로그인 (비밀번호 + OTP) 후 관리 콘솔 진입", s == 200 and "사용자와 암호화된 개인정보" in html, url)
    s, url, html, _, _ = admin.post("/idp/admin", {"csrf": csrf(html), "action": "create", "username": username,
                                                   "name": "테스트사용자", "password": password, "rrn": rrn,
                                                   "phone": "010-5555-" + run_id[-4:]})
    check("새 사용자 생성", f"{username} 사용자를 만들었습니다" in html, username)
    s, url, html, _, _ = admin.post("/idp/admin", {"csrf": csrf(html), "action": "create", "username": username + "x",
                                                   "name": "중복", "password": password, "rrn": rrn, "phone": ""})
    check("같은 주민등록번호 중복 가입 차단 (블라인드 인덱스로 암호문 상태에서 비교)", "같은 주민등록번호" in html)

    # ------------------------------------------------------------------ normal flow
    section("1. 로그인 → OTP 등록 → 서비스 접속")
    b = Browser()
    s, url, html, chain, _ = b.get("/portal/")
    authz = next((u for u in chain if "/idp/authorize" in u), "")
    q = urllib.parse.parse_qs(urllib.parse.urlparse(authz).query)
    check("포털 접속 시 IdP 로그인으로 이동", url.endswith("/idp/login"), " → ".join(urllib.parse.urlparse(u).path for u in chain))
    check("인가 요청에 state와 nonce 포함", bool(q.get("state")) and bool(q.get("nonce")))

    s, url, html2, _, _ = b.post("/idp/login", {"csrf": csrf(html), "username": username, "password": "wrong"})
    check("틀린 비밀번호 거부 (계정 존재 여부를 드러내지 않는 같은 메시지)", "아이디 또는 비밀번호가 올바르지 않습니다" in html2)
    s, url, html3, _, _ = b.post("/idp/login", {"csrf": csrf(html2), "username": "nobody", "password": "x"})
    check("없는 아이디도 같은 메시지", "아이디 또는 비밀번호가 올바르지 않습니다" in html3)

    s, url, html, chain, _ = b.post("/idp/login", {"csrf": csrf(html3), "username": username, "password": password})
    check("비밀번호 확인 후 첫 로그인이면 OTP 등록 화면", url.endswith("/otp/enroll"))
    secret = re.search(r'class="secret">([A-Z2-7 ]+)<', html).group(1)
    s, url, html4, _, _ = b.post("/idp/otp/enroll", {"csrf": csrf(html), "code": "000000"})
    check("틀린 OTP로는 등록 안 됨", "코드가 맞지 않습니다" in html4)
    used_step = int(time.time()) // 30
    s, url, html, chain, _ = b.post("/idp/otp/enroll", {"csrf": csrf(html4), "code": totp(secret, used_step)})
    callback = next((u for u in chain if "/portal/callback" in u), "")
    check("Python으로 계산한 TOTP로 등록 성공 (표준 인증 앱 호환)", url.endswith("/portal/") and "테스트사용자" in html,
          " → ".join(urllib.parse.urlparse(u).path for u in chain))
    check("ID 토큰 서명·aud·nonce 검증 후 포털 로그인", "RS256" in html and '"aud" : "portal"' in html)

    # ------------------------------------------------------------------ SSO
    section("2. SSO: 다른 서비스는 다시 로그인하지 않음")
    s, url, html, chain, _ = b.get("/mail/")
    paths = [urllib.parse.urlparse(u).path for u in chain]
    check("웹메일 접속 시 로그인·OTP 화면 없이 바로 진입", url.endswith("/mail/") and "웹메일" in html
          and not any(p.endswith("/login") or "/otp" in p for p in paths), " → ".join(paths))
    sid_portal = re.search(r'"sid" : "([^"]+)"', b.get("/portal/")[2]).group(1)
    sid_mail = re.search(r'"sid" : "([^"]+)"', html).group(1)
    check("두 서비스가 같은 IdP 세션(sid)을 공유", sid_portal == sid_mail, sid_portal)

    # ------------------------------------------------------------------ code / token attacks
    section("3. 인가 코드·토큰 공격 방어")
    code = urllib.parse.parse_qs(urllib.parse.urlparse(callback).query).get("code", [""])[0]
    auth = base64.b64encode(f"portal:{PORTAL_SECRET}".encode()).decode()
    s, _, body, _, _ = Browser().post("/idp/token", {"grant_type": "authorization_code", "code": code,
                                                    "redirect_uri": BASE + "/portal/callback"},
                                      headers={"Authorization": "Basic " + auth}, follow=False)
    check("이미 사용된 인가 코드 재사용 거부 (일회용)", s == 400 and "invalid_grant" in body, f"HTTP {s} {body}")
    bad = base64.b64encode(b"portal:wrong-secret").decode()
    s, _, body, _, _ = Browser().post("/idp/token", {"grant_type": "authorization_code", "code": "x",
                                                    "redirect_uri": BASE + "/portal/callback"},
                                      headers={"Authorization": "Basic " + bad}, follow=False)
    check("클라이언트 시크릿이 틀리면 토큰 발급 거부", s == 401 and "invalid_client" in body, f"HTTP {s}")
    s, url, body, _, hdrs = Browser().get("/idp/authorize?response_type=code&client_id=portal&state=a&nonce=b"
                                          "&redirect_uri=" + urllib.parse.quote("http://evil.example/callback"),
                                          follow=False)
    check("등록되지 않은 redirect_uri는 리다이렉트하지 않고 거부 (오픈 리다이렉트·코드 탈취 방지)",
          s == 400 and not hdrs.get("Location"), f"HTTP {s}")
    s, *_ = Browser().get("/idp/authorize?response_type=code&client_id=evil&state=a&nonce=b&redirect_uri=x",
                          follow=False)
    check("등록되지 않은 client_id 거부", s == 400, f"HTTP {s}")
    c = Browser()
    c.get("/portal/", follow=False)
    s, url, body, _, _ = c.get("/portal/callback?code=abc&state=forged")
    check("state가 다른 콜백 거부 (로그인 CSRF 방지)", s == 400 and "state" in body, f"HTTP {s}")

    hdr = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    pl = base64.urlsafe_b64encode(json.dumps({"iss": BASE + "/idp", "aud": "mail", "sid": sid_mail,
                                              "iat": int(time.time()), "jti": "x",
                                              "events": {"http://schemas.openid.net/event/backchannel-logout": {}}})
                                  .encode()).rstrip(b"=").decode()
    s, _, body, _, _ = Browser().post("/mail/backchannel-logout", {"logout_token": f"{hdr}.{pl}."}, follow=False)
    check("서명 없는(alg=none) 위조 로그아웃 토큰 거부", s == 400, f"HTTP {s} {body}")
    s, url, html, _, _ = b.get("/mail/")
    check("위조 토큰으로는 세션이 끊기지 않음", url.endswith("/mail/") and "웹메일" in html)

    # ------------------------------------------------------------------ web attacks
    section("4. 웹 보안")
    s, url, body, _, _ = Browser().post("/idp/login", {"username": username, "password": password})
    check("CSRF 토큰 없는 로그인 POST 거부", s == 400 and "CSRF" in body, f"HTTP {s}")
    s, url, body, _, hdrs = b.get("/idp/")
    check("보안 헤더: X-Frame-Options DENY, CSP, no-store",
          hdrs.get("X-Frame-Options") == "DENY" and "frame-ancestors 'none'" in (hdrs.get("Content-Security-Policy") or "")
          and hdrs.get("Cache-Control") == "no-store")
    p = Browser()
    _, _, _, _, h = p.get("/idp/login", follow=False)
    cookie = h.get("Set-Cookie") or ""
    check("세션 쿠키 HttpOnly + SameSite=Lax", "HttpOnly" in cookie and "SameSite=Lax" in cookie, cookie.split(";")[0][:20] + "...")
    s, url, body, _, _ = b.get("/idp/admin")
    check("일반 사용자의 관리 콘솔 접근 차단 (DB 권한 재확인)", s == 403, f"HTTP {s}")

    # ------------------------------------------------------------------ OTP replay & lockout
    section("5. OTP 재사용·무차별 대입 방어")
    r = Browser()
    s, url, html, _, _ = r.get("/portal/")
    s, url, html, _, _ = r.post("/idp/login", {"csrf": csrf(html), "username": username, "password": password})
    s, url, html, _, _ = r.post("/idp/otp", {"csrf": csrf(html), "code": totp(secret, used_step)})
    check("이미 사용한 OTP 코드 재사용 거부 (리플레이 방지)", "이미 사용된 OTP" in html or "올바르지 않습니다" in html)
    s, url, html, _, _ = r.post("/idp/otp", {"csrf": csrf(html), "code": totp(secret, int(time.time()) // 30 + 1)})
    check("새 코드로는 정상 로그인", url.endswith("/portal/"), urllib.parse.urlparse(url).path)

    lock = Browser()
    s, url, html, _, _ = lock.get("/idp/login")
    msg = ""
    for i in range(5):
        s, url, html, _, _ = lock.post("/idp/login", {"csrf": csrf(html), "username": "user2", "password": f"bad{i}"})
        msg = html
    check("비밀번호 5회 실패 시 계정 잠금", "계정을 5분간 잠갔습니다" in msg)
    s, url, html, _, _ = lock.post("/idp/login", {"csrf": csrf(html), "username": "user2", "password": "User!2345"})
    check("잠긴 동안은 올바른 비밀번호도 거부", "계정이 잠겼습니다" in html)
    s, url, html, _, _ = admin.get("/idp/admin")
    uid = re.search(r'<td>(\d+)</td>\s*<td>user2<', html)
    if uid:
        admin.post("/idp/admin", {"csrf": csrf(html), "action": "unlock", "id": uid.group(1)})

    # ------------------------------------------------------------------ DB encryption
    section("6. DB 암호화·키 관리 (Oracle)")
    s, url, html, _, _ = admin.get("/idp/admin")
    check("관리 콘솔이 Oracle에 연결됨", "Oracle" in html, re.search(r"저장소: ([^<]+)<", html).group(1).strip())
    try:
        out = subprocess.run(["docker", "compose", "exec", "-T", "oracle", "bash", "-c",
                              "echo \"SET HEADING OFF\nSET FEEDBACK OFF\nSELECT USERNAME||'|'||RRN_ENC FROM TG_USERS "
                              f"WHERE USERNAME='{username}';\" | sqlplus -s trustgate/TrustGate_1@//localhost:1521/FREEPDB1"],
                             capture_output=True, text=True, timeout=60,
                             cwd=pathlib.Path(__file__).resolve().parent.parent).stdout.strip()
        digits = rrn.replace("-", "")
        check("Oracle에 직접 조회해도 주민등록번호 평문이 없음", out.startswith(username) and digits not in out
              and "|v" in out, out[:70] + "...")
    except Exception as e:  # docker not on PATH, etc.
        check("Oracle 직접 조회", False, str(e))
    before = re.findall(r"v(\d+) = (\d+)개", html)
    s, url, html, _, _ = admin.post("/idp/admin", {"csrf": csrf(html), "action": "rotate"})
    m = re.search(r"새 데이터 키 v(\d+)", html)
    check("데이터 키 교체 (새 버전 활성화)", bool(m), f"v{m.group(1) if m else '?'}")
    s, url, html, _, _ = admin.post("/idp/admin", {"csrf": csrf(html), "action": "reencrypt"})
    after = re.findall(r"v(\d+) = (\d+)개", html)
    check("재암호화 후 모든 값이 새 키 버전 하나로 이동", len(after) == 1 and m and after[0][0] == m.group(1),
          f"전 {before} → 후 {after}")
    s, url, html, _, _ = b.get("/portal/")
    s, url, html, _, _ = b.get("/idp/")
    check("키 교체 후에도 사용자 정보 복호화·마스킹 정상", rrn[:6] + "-1******" in html)
    s, url, html, _, _ = admin.post("/idp/admin", {"csrf": csrf(admin.get("/idp/admin")[2]), "action": "search", "rrn": rrn})
    check("암호화된 주민등록번호를 블라인드 인덱스로 검색", username in html)

    # ------------------------------------------------------------------ single logout
    section("7. 통합 로그아웃 (Back-Channel Logout)")
    s, url, html, _, _ = b.get("/portal/")
    s, url, html, chain, _ = b.post("/portal/logout", {"csrf": csrf(html)})
    check("포털에서 로그아웃하면 IdP를 거쳐 로그아웃 완료 화면", url.endswith("/portal/logged-out"),
          " → ".join(urllib.parse.urlparse(u).path for u in chain))
    s, url, html, chain, _ = b.get("/mail/")
    check("웹메일 세션도 IdP 통보로 이미 종료됨 (다시 로그인 요구)", url.endswith("/idp/login"),
          " → ".join(urllib.parse.urlparse(u).path for u in chain))

    passed = sum(1 for r in results if r.get("ok"))
    total = sum(1 for r in results if "ok" in r)
    print(f"\n\033[1m{passed}/{total} checks passed\033[0m")
    if OUT:
        with open(OUT, "w", encoding="utf-8") as f:
            json.dump({"base": BASE, "passed": passed, "total": total, "results": results}, f, ensure_ascii=False, indent=1)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
