<%@ include file="header.jspf" %>
<c:set var="title" value="홈"/>
<%@ include file="head.jspf" %>
<body>
<div class="top">
  <div class="brand"><c:out value="${spName}"/> <span class="tag">SSO 연동 서비스 · /<c:out value="${clientId}"/></span></div>
  <nav>
    <a href="${otherUrl}"><c:out value="${otherName}"/>로 이동</a>
    <form class="inline-form" method="post" action="${pageContext.request.contextPath}/logout">
      <input type="hidden" name="csrf" value="${csrf}">
      <button class="small ghost">로그아웃 (전체)</button>
    </form>
  </nav>
</div>
<main>
  <div class="card">
    <h1><c:out value="${user.name()}"/>님, <c:out value="${spName}"/>에 오신 것을 환영합니다</h1>
    <p class="sub">이 서비스는 비밀번호를 직접 받지 않습니다. TrustGate IdP가 서명한 ID 토큰을 검증해서 로그인 상태를 만듭니다.</p>
    <div class="alert info">
      <b><c:out value="${otherName}"/></b>로 이동해 보세요. IdP에 이미 로그인되어 있어서 비밀번호와 OTP를 다시 묻지 않고 바로 들어갑니다.
      여기서 로그아웃하면 IdP가 두 서비스 모두에 로그아웃을 통보합니다.
    </div>
    <a class="btn" href="${otherUrl}"><c:out value="${otherName}"/> 열기</a>
  </div>
  <div class="grid2">
    <div class="card">
      <h2>검증한 사용자 정보</h2>
      <dl class="kv">
        <dt>사용자 (sub)</dt><dd><c:out value="${user.sub()}"/></dd>
        <dt>권한</dt><dd><c:out value="${user.role()}"/></dd>
        <dt>인증 수단 (amr)</dt><dd><c:out value="${user.amr()}"/></dd>
        <dt>IdP 세션 (sid)</dt><dd class="mono"><c:out value="${user.sid()}"/></dd>
      </dl>
      <h2 style="margin-top:18px">이 서비스가 확인한 항목</h2>
      <ul class="steps">
        <li>state 일치 (로그인 응답 위조 방지)</li>
        <li>인가 코드를 서버 간 통신(Back-Channel)으로 ID 토큰과 교환</li>
        <li>RS256 서명을 IdP 공개키(JWKS)로 검증. alg=none 등 다른 알고리즘은 거부</li>
        <li>iss, aud(=<c:out value="${clientId}"/>), exp, iat, nonce 확인</li>
        <li>로그인 후 세션 ID 재발급 (세션 고정 공격 방지)</li>
      </ul>
    </div>
    <div class="card">
      <h2>받은 ID 토큰 (JWT)</h2>
      <label>Header</label>
      <pre class="cipher" style="white-space:pre-wrap"><c:out value="${user.headerJson()}"/></pre>
      <label>Payload</label>
      <pre class="cipher" style="white-space:pre-wrap"><c:out value="${user.payloadJson()}"/></pre>
      <label>원본 토큰</label>
      <div class="cipher"><c:out value="${user.idToken()}"/></div>
    </div>
  </div>
</main>
</body>
</html>
