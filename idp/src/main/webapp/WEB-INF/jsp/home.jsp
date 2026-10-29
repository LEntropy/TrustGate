<%@ include file="header.jspf" %>
<c:set var="title" value="내 계정"/>
<%@ include file="head.jspf" %>
<body>
<div class="top">
  <div class="brand">TrustGate <span class="tag">통합인증 IdP</span></div>
  <nav>
    <c:if test="${user.isAdmin()}"><a href="${pageContext.request.contextPath}/admin">보안 관리 콘솔</a></c:if>
    <a href="${pageContext.request.contextPath}/logout">로그아웃</a>
  </nav>
</div>
<main>
  <div class="card">
    <h1><c:out value="${user.displayName()}"/>님, 로그인되어 있습니다</h1>
    <p class="sub">TrustGate에 로그인된 동안에는 아래 서비스에 다시 로그인하지 않고 들어갈 수 있습니다.</p>
    <div class="services">
      <c:forEach var="cl" items="${clients}">
        <a class="service" href="${cl.baseUrl()}/">
          <b><c:out value="${cl.name()}"/></b>
          <span><c:out value="${cl.baseUrl()}"/></span><br>
          <c:choose>
            <c:when test="${connected.contains(cl.id())}"><span class="pill ok">이 세션으로 접속함</span></c:when>
            <c:otherwise><span class="pill info">클릭하면 바로 로그인</span></c:otherwise>
          </c:choose>
        </a>
      </c:forEach>
    </div>
  </div>
  <div class="grid2">
    <div class="card">
      <h2>내 정보</h2>
      <dl class="kv">
        <dt>아이디</dt><dd><c:out value="${user.username()}"/></dd>
        <dt>권한</dt><dd><c:out value="${user.role()}"/></dd>
        <dt>주민등록번호</dt><dd><c:out value="${rrn}"/></dd>
        <dt>휴대폰</dt><dd><c:out value="${phone}"/></dd>
        <dt>이메일</dt><dd><c:out value="${email}"/></dd>
      </dl>
      <p class="muted" style="margin-top:12px">개인정보는 DB에 암호화되어 있고, 화면에는 복호화한 뒤 마스킹해서만 보여줍니다.</p>
    </div>
    <div class="card">
      <h2>현재 SSO 세션</h2>
      <dl class="kv">
        <dt>세션 ID (sid)</dt><dd class="mono"><c:out value="${sso.sid()}"/></dd>
        <dt>인증 수단</dt><dd>비밀번호 + OTP <span class="pill ok">2단계 인증</span></dd>
        <dt>2차 인증</dt><dd><c:out value="${user.otpEnabled() ? 'TOTP 등록됨' : '미등록'}"/></dd>
      </dl>
    </div>
  </div>
</main>
</body>
</html>
