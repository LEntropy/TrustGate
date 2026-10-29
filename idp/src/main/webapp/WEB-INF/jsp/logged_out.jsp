<%@ include file="header.jspf" %>
<c:set var="title" value="로그아웃"/>
<%@ include file="head.jspf" %>
<body>
<div class="top"><div class="brand">TrustGate <span class="tag">통합인증 IdP</span></div></div>
<main class="narrow">
  <div class="card">
    <h1>로그아웃했습니다</h1>
    <p class="sub">통합인증 세션을 끝냈습니다.</p>
    <c:if test="${not empty results}">
      <h2>연결된 서비스에 로그아웃 통보 (Back-Channel)</h2>
      <c:forEach var="r" items="${results}">
        <div class="alert ${r.ok() ? 'ok' : 'error'}">
          <c:out value="${r.name()}"/>: <c:out value="${r.ok() ? '세션 종료됨' : '통보 실패'}"/>
          <span class="muted">(<c:out value="${r.detail()}"/>)</span>
        </div>
      </c:forEach>
    </c:if>
    <a class="btn" href="${pageContext.request.contextPath}/login">다시 로그인</a>
  </div>
</main>
</body>
</html>
