# TrustGate

Java/JSP로 만든 **통합인증(SSO) + 2차 인증(TOTP) + DB 개인정보 암호화·키 관리** 프로젝트입니다.
인증 서버(IdP) 하나와 그 인증을 함께 쓰는 서비스(SP) 두 개를 Tomcat 10.1과 Oracle Database Free 위에서 실행합니다.

- **SSO**: OpenID Connect 인가 코드 흐름(Authorization Code Flow)을 서블릿으로 직접 구현했습니다. 한 번 로그인하면 다른 서비스에는 다시 로그인하지 않고, 한 곳에서 로그아웃하면 모든 서비스가 함께 로그아웃됩니다(Back-Channel Logout).
- **2차 인증**: RFC 6238 TOTP를 직접 구현했습니다. Google Authenticator, Microsoft Authenticator와 호환되며 QR 코드로 등록합니다.
- **DB 암호화**: 주민등록번호, 전화번호, OTP 비밀키를 AES-256-GCM으로 컬럼 단위 암호화합니다. KEK/DEK 2단계 키 구조, 키 교체와 재암호화, 암호문 검색용 블라인드 인덱스, 화면 마스킹을 포함합니다.

```
                    ┌──────────────────────── Tomcat 10.1 ────────────────────────┐
 브라우저 ──────────►│  /portal (SP)        /mail (SP)          /idp (IdP)          │
                    │   AuthFilter          AuthFilter           login → OTP        │
                    │   /callback ◄─code─── /callback ◄──code─── /authorize         │
                    │       └──── 서버 간 통신: /token (코드 → ID 토큰) ────►        │
                    │       ◄──── /backchannel-logout (서명된 로그아웃 토큰) ────     │
                    │   JWKS로 RS256 서명 검증                    /admin (관리 콘솔) │
                    └──────────────────────────────────────────────────┬──────────┘
                                                                       │ JDBC (HikariCP)
                         KEK (PKCS#12 키스토어) ── 감싸기 ──► DEK ──► Oracle: TG_USERS / TG_KEYS / TG_AUDIT
```

> **처음 써 보시나요?** [테스트 가이드](docs/TEST_GUIDE.md)에서 설치부터 테스트 10가지까지 화면과 함께 하나씩 따라 할 수 있습니다. 각 단계가 어떤 원리로 동작하고 무엇을 막기 위한 것인지도 설명합니다.

## 구성

| 모듈 | 내용 |
|---|---|
| `core` | 서블릿과 무관한 공통 라이브러리: TOTP, Base32, PBKDF2, AES-GCM, KEK/DEK 키 관리, 컬럼 암호화, 블라인드 인덱스, 마스킹, JWT(RS256), JWKS, DAO, 보안 헤더 필터 |
| `idp` | 인증 서버: 로그인, OTP 등록·인증, `/authorize`, `/token`, `/jwks`, 통합 로그아웃, 내 계정, 보안 관리 콘솔 |
| `sp` | SSO 연동 서비스. 같은 WAR를 `/portal`(사내 포털)과 `/mail`(웹메일)로 두 번 배포하고, 컨텍스트 경로로 어떤 클라이언트인지 구분합니다 |

사용한 라이브러리: Jakarta Servlet 6 / JSP / JSTL, Jackson(JSON), HikariCP(커넥션 풀), ojdbc11, H2(테스트), ZXing(QR 생성), JUnit 5.
암호 연산(TOTP, PBKDF2, AES-GCM, RSA 서명, HMAC)은 모두 JDK 표준 API(JCA)로 구현했습니다.

## 로그인 흐름

```
 1. 사용자가 /portal 접속 → 세션 없음 → IdP /authorize 로 이동 (client_id, redirect_uri, state, nonce)
 2. IdP: client_id 확인, redirect_uri 정확히 일치 확인 → 로그인 화면
 3. 비밀번호 확인(PBKDF2) → 세션 ID 재발급 → OTP 화면 (처음이면 QR 등록 화면)
 4. TOTP 확인 + 같은 시간 단계 재사용 차단 → SSO 세션 생성 → 일회용 인가 코드와 함께 /portal/callback 으로
 5. 포털: state 확인 → 서버 간 통신으로 코드를 ID 토큰과 교환(클라이언트 시크릿 인증)
         → RS256 서명(JWKS 공개키), iss, aud, exp, iat, nonce 확인 → 세션 ID 재발급 → 로그인 완료
 6. 사용자가 /mail 접속 → IdP에 SSO 세션이 있으므로 로그인 화면 없이 4번부터 바로 진행
 7. 포털에서 로그아웃 → IdP가 이 SSO 세션(sid)으로 토큰을 받은 모든 서비스에 서명된 로그아웃 토큰 전송
```

## 보안 설계

| 위협 | 대응 | 위치 |
|---|---|---|
| 비밀번호 유출 | PBKDF2-HMAC-SHA256 31만 회, 사용자별 salt, 상수 시간 비교 | `PasswordHasher` |
| 아이디 존재 여부 노출 | 없는 아이디와 틀린 비밀번호에 같은 메시지, 같은 계산 시간 | `LoginServlet` |
| 무차별 대입 | 비밀번호·OTP 5회 실패 시 계정 5분 잠금, OTP 5회 실패 시 로그인 처음부터 | `UserDao.recordFailure` |
| OTP 재사용 | 사용한 시간 단계를 저장하고 `UPDATE ... WHERE OTP_LAST_STEP < ?`로 원자적으로 차단 | `UserDao.consumeOtpStep` |
| 세션 고정 | 비밀번호 확인 후, 로그인 완료 후 세션 ID 재발급 | `Flow.complete`, `CallbackServlet` |
| 인가 코드 탈취·재사용 | 60초 만료, 일회용, 발급받은 client_id·redirect_uri와 일치해야 교환 | `AuthCodeStore`, `TokenServlet` |
| 오픈 리다이렉트 | 등록된 redirect_uri와 정확히 일치하지 않으면 리다이렉트 없이 오류 화면 | `AuthorizeServlet` |
| 로그인 위조(CSRF) | 요청마다 새 `state`, 토큰 재전송 방지용 `nonce` | `AuthFilter`, `CallbackServlet` |
| 토큰 위조 | RS256만 허용. `alg=none`, RS256→HS256 키 혼동 공격 거부. kid로 JWKS 공개키 선택 | `Jwt.verify` |
| 위조 로그아웃 요청 | 서명, iss, aud, iat, events, sid 확인, nonce 금지, jti 재사용 차단 | `BackchannelLogoutServlet` |
| 폼 CSRF | 세션별 CSRF 토큰(Synchronizer Token), SameSite=Lax 쿠키 | `Web`, `context.xml` |
| XSS·클릭재킹 | JSTL `c:out` 출력 이스케이프, CSP, `X-Frame-Options: DENY`, HttpOnly 쿠키 | `SecurityHeadersFilter` |
| SQL 인젝션 | 모든 쿼리 PreparedStatement 바인딩 | `UserDao`, `AuditDao` |
| 권한 상승 | 관리 콘솔 접근 시 세션이 아니라 DB의 권한을 다시 확인 | `AdminServlet` |
| 감사 추적 | 로그인 성공·실패, OTP, 토큰 발급, 로그아웃, 키 교체, 개인정보 검색을 기록(검색값은 마스킹해서 기록) | `AuditDao` |

### DB 암호화와 키 관리

```
 KEK (AES-256, PKCS#12 키스토어 파일)          ← HSM·KMS로 바꿀 수 있도록 KekProvider 인터페이스로 분리
  └─ 감싸기(AES-GCM) ─► DEK v1, v2, ... (TG_KEYS 테이블에 감싼 상태로 저장)
                         └─ 암호화 ─► TG_USERS.RRN_ENC = "v2:" + base64(nonce ‖ 암호문 ‖ 태그)
 별도 인덱스 키 ── HMAC-SHA256 ─► TG_USERS.RRN_IDX (블라인드 인덱스, 일치 검색용)
```

- **AAD로 위치 고정**: 암호화할 때 `TG_USERS.RRN_ENC:<행 ID>`를 AES-GCM의 추가 인증 데이터로 넣습니다. 그래서 다른 행이나 컬럼에 복사한 암호문은 복호화되지 않습니다.
- **키 교체**: 관리 콘솔에서 새 DEK를 만들면 새 값은 새 키로 암호화되고, 기존 값은 이전 키로 계속 복호화됩니다. "재암호화"를 누르면 모든 값을 활성 키로 옮깁니다. 키 버전별 값 개수를 화면에서 확인할 수 있습니다.
- **검색**: 같은 평문도 매번 다른 암호문이 되므로, 검색과 중복 가입 확인은 별도 키로 만든 HMAC 값으로 합니다. 검색 토큰에서는 평문이나 암호문을 알아낼 수 없습니다.
- **서명 키 보호**: IdP의 RSA 토큰 서명 개인키도 KEK로 감싸서 저장합니다.

## 실행

Docker Desktop만 있으면 됩니다.

```bash
docker compose up -d --build
```

http://localhost:8080 에서 시작합니다. 첫 실행 때 테이블, 키, 데모 계정이 자동으로 만들어집니다.

| 계정 | 비밀번호 | 권한 |
|---|---|---|
| `admin` | `Admin!2345` | 관리자 (`/idp/admin` 보안 관리 콘솔) |
| `user1`, `user2` | `User!2345` | 일반 사용자 |

데모 계정의 주민등록번호와 전화번호는 임의로 만든 값입니다. 처음 로그인하면 OTP 등록 화면에서 휴대폰 인증 앱으로 QR을 스캔합니다.
`TG_DEMO_MODE=true`(기본값)이면 OTP 화면에 현재 코드가 함께 표시되어 휴대폰 없이도 시험할 수 있습니다. 실제 운영 환경을 가정하면 `false`로 꺼야 합니다.

주요 환경 변수: `TG_DB_URL`, `TG_DB_USER`, `TG_DB_PASSWORD`, `TG_KEK_PASSWORD`, `TG_CLIENT_PORTAL_SECRET`, `TG_CLIENT_MAIL_SECRET`, `TG_DEMO_MODE`.
compose의 값은 데모용 기본값입니다. `TG_DB_URL`을 지정하지 않으면 H2(Oracle 호환 모드) 파일 DB로 동작합니다.

## 테스트

```powershell
powershell -ExecutionPolicy Bypass -File .\run_tests.ps1
```

1. **단위 테스트 (JUnit 5, 38개)**: RFC 6238·RFC 4648 테스트 벡터, PBKDF2, 암호문 변조·AAD 불일치·다른 KEK 거부, 키 교체 후 복호화와 재암호화, 블라인드 인덱스 검색, OTP 재사용 차단, 계정 잠금, JWT 변조·`alg=none`·HS256 키 혼동·외부 키 서명 거부, ID 토큰·로그아웃 토큰 클레임 검증
2. **End-to-End (36개 항목)**: Tomcat + Oracle을 띄우고, 쿠키·리다이렉트·CSRF 토큰을 처리하는 Python 클라이언트로 실제 HTTP 흐름을 실행합니다. OTP 코드는 서버와 별개로 Python에서 계산해서 표준 인증 앱과 호환되는지도 확인합니다. Oracle에 직접 SQL로 조회해 평문이 저장되지 않았는지도 확인합니다.
3. 결과를 `test-results/report.html`로 정리합니다.

데이터베이스에 실제로 저장된 값(암호문, 블라인드 인덱스, 감싼 키)은 `show_db.ps1`로 바로 볼 수 있습니다.

```
== 2. SSO: 다른 서비스는 다시 로그인하지 않음 ==
  [PASS] 웹메일 접속 시 로그인·OTP 화면 없이 바로 진입  (/mail/ → /idp/authorize → /mail/callback → /mail/)
  [PASS] 두 서비스가 같은 IdP 세션(sid)을 공유
== 6. DB 암호화·키 관리 (Oracle) ==
  [PASS] Oracle에 직접 조회해도 주민등록번호 평문이 없음  (e2e258928|v3:KcVnLkWcGZ2elyuNcd+n61ys...)
  [PASS] 재암호화 후 모든 값이 새 키 버전 하나로 이동  (전 [('3', '24')] → 후 [('4', '24')])
== 7. 통합 로그아웃 (Back-Channel Logout) ==
  [PASS] 웹메일 세션도 IdP 통보로 이미 종료됨 (다시 로그인 요구)  (/mail/ → /idp/authorize → /idp/login)

36/36 checks passed
```

## 테스트 중 발견한 문제와 해결

| 증상 | 원인 | 해결 |
|---|---|---|
| Oracle로 바꾸자 IdP 배포 실패 (`No suitable driver`) | `WEB-INF/lib`의 JDBC 드라이버는 Tomcat에서 `DriverManager` 자동 등록 대상이 아님 | URL에 따라 HikariCP에 드라이버 클래스를 명시 |
| 화면의 한글이 깨짐 | JSP 본문 파일의 인코딩이 지정되지 않아 ISO-8859-1로 읽힘. include한 조각의 `pageEncoding`은 그 조각에만 적용됨 | `web.xml`의 `jsp-property-group`으로 모든 JSP·조각을 UTF-8로 지정 |
| E2E 테스트가 요청마다 약 2초씩 지연 | Windows에서 `localhost`가 IPv6(::1)로 먼저 연결을 시도하는데, 컨테이너 포트는 IPv4에만 열려 있음 | 테스트 클라이언트가 IPv4를 먼저 시도하도록 변경 (브라우저는 영향 없음) |
| 관리 콘솔 주소로 들어와 로그인하면 관리 콘솔이 아니라 "내 계정"으로 이동 | 로그인 완료 후 이동할 곳이 IdP 첫 화면으로 고정되어 있었음 (테스트 가이드를 직접 따라 하다 발견) | 서버가 정한 경로만 세션에 기억했다가 로그인 후 그 화면으로 돌려보냄. 요청 값으로 받지 않으므로 오픈 리다이렉트가 생기지 않음 |
| 감사 로그에서 `ACCOUNT_UNLOCKED`가 실패처럼 빨간색으로 표시 | 이벤트 이름에 `LOCK`이 들어가면 빨간색으로 칠하는 조건이 `UNLOCK`까지 잡음 | 실패·잠금·차단 이벤트를 정확한 이름으로 구분 |
| OTP 재사용 테스트 직후, 데모 상자에 방금 쓴 코드가 그대로 보임 | 같은 30초 구간 안이라 정상 동작이지만, 처음 쓰는 사람은 "새 코드"를 찾지 못함 | 테스트 가이드에 30초 대기 후 화면을 다시 여는 방법을 안내 |
| 관리자 사용자 추가가 E2E에서만 실패 | 테스트가 폼이 없는 페이지에서 CSRF 토큰을 읽어 빈 값으로 전송했고, 서버가 정상적으로 거부함 | 테스트가 관리 콘솔 페이지의 토큰을 쓰도록 수정. CSRF 방어가 의도대로 동작함을 확인 |

## 한계와 다음 단계

- **FIDO2/WebAuthn**: 생체인증 기반 2차 인증은 아직 없습니다. 2차 인증 수단을 늘릴 수 있게 `amr` 클레임에 인증 수단을 기록해 두었습니다.
- **HSM·KMS 연동**: 지금 KEK는 PKCS#12 파일에 있습니다. `KekProvider` 인터페이스만 구현하면 KEK를 밖으로 꺼내지 않는 HSM이나 클라우드 KMS로 바꿀 수 있습니다.
- **다중 서버**: 인가 코드와 SSO 세션 목록이 메모리에 있어서 IdP 한 대를 전제로 합니다. 여러 대로 늘리려면 DB나 Redis로 옮겨야 합니다.
- **블라인드 인덱스 키 교체**: 데이터 키는 교체되지만 인덱스 키는 고정입니다. 교체하려면 전체 인덱스를 다시 계산하는 작업이 필요합니다.
- **HTTPS**: 로컬 데모라서 HTTP입니다. 실제 환경에서는 TLS와 `Secure` 쿠키가 필요합니다.
- PKCE, Refresh Token, IP 단위 요청 제한은 구현하지 않았습니다.
