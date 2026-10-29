<%@ include file="header.jspf" %>
<c:set var="title" value="로그인"/>
<%@ include file="head.jspf" %>
<body>
<div class="top"><div class="brand">TrustGate <span class="tag">통합인증 IdP</span></div></div>
<main class="narrow">
  <div class="card">
    <h1>로그인</h1>
    <c:choose>
      <c:when test="${not empty clientName}">
        <p class="sub"><b><c:out value="${clientName}"/></b>에 접속하려면 로그인하세요. 한 번 로그인하면 다른 서비스도 다시 로그인하지 않고 쓸 수 있습니다.</p>
      </c:when>
      <c:otherwise><p class="sub">TrustGate 통합 계정으로 로그인합니다.</p></c:otherwise>
    </c:choose>
    <c:if test="${not empty flash}"><div class="alert info"><c:out value="${flash}"/></div></c:if>
    <c:if test="${not empty error}"><div class="alert error"><c:out value="${error}"/></div></c:if>
    <form method="post" action="${pageContext.request.contextPath}/login" autocomplete="off">
      <input type="hidden" name="csrf" value="${csrf}">
      <label for="username">아이디</label>
      <input type="text" id="username" name="username" value="<c:out value='${username}'/>" required autofocus>
      <label for="password">비밀번호</label>
      <input type="password" id="password" name="password" required>
      <button type="submit" class="wide">다음</button>
    </form>
    <p class="muted" style="margin-top:14px">비밀번호 확인 후 OTP(2차 인증)를 입력합니다. 5회 연속 실패하면 계정이 5분간 잠깁니다.</p>
    <c:if test="${demoMode}">
      <div class="demo">데모 계정: <code>user1</code> / <code>User!2345</code> · 관리자 <code>admin</code> / <code>Admin!2345</code></div>
    </c:if>
  </div>
</main>
</body>
</html>
