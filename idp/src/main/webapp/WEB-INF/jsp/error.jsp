<%@ include file="header.jspf" %>
<c:set var="title" value="오류"/>
<%@ include file="head.jspf" %>
<body>
<div class="top"><div class="brand">TrustGate <span class="tag">통합인증 IdP</span></div></div>
<main class="narrow">
  <div class="card">
    <h1>요청을 처리할 수 없습니다</h1>
    <div class="alert error"><c:out value="${empty message ? '알 수 없는 오류가 발생했습니다.' : message}"/></div>
    <a class="btn ghost" href="${pageContext.request.contextPath}/">처음으로</a>
  </div>
</main>
</body>
</html>
