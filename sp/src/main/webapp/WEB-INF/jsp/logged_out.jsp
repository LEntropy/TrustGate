<%@ include file="header.jspf" %>
<c:set var="title" value="로그아웃"/>
<%@ include file="head.jspf" %>
<body>
<div class="top"><div class="brand"><c:out value="${spName}"/> <span class="tag">SSO 연동 서비스</span></div></div>
<main class="narrow">
  <div class="card">
    <h1>로그아웃했습니다</h1>
    <p class="sub"><c:out value="${spName}"/>와 TrustGate 통합인증 세션이 모두 끝났습니다. <c:out value="${otherName}"/>도 IdP의 통보를 받아 함께 로그아웃되었습니다.</p>
    <a class="btn" href="${pageContext.request.contextPath}/">다시 로그인</a>
    <a class="btn ghost" href="${otherUrl}"><c:out value="${otherName}"/> 열어 보기</a>
  </div>
</main>
</body>
</html>
