<%@ include file="header.jspf" %>
<c:set var="title" value="오류"/>
<%@ include file="head.jspf" %>
<body>
<div class="top"><div class="brand"><c:out value="${spName}"/> <span class="tag">SSO 연동 서비스</span></div></div>
<main class="narrow">
  <div class="card">
    <h1>로그인을 완료하지 못했습니다</h1>
    <div class="alert error"><c:out value="${empty message ? '알 수 없는 오류가 발생했습니다.' : message}"/></div>
    <a class="btn ghost" href="${pageContext.request.contextPath}/">다시 시도</a>
  </div>
</main>
</body>
</html>
