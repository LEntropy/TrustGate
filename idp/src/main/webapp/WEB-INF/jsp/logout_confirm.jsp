<%@ include file="header.jspf" %>
<c:set var="title" value="로그아웃 확인"/>
<%@ include file="head.jspf" %>
<body>
<div class="top"><div class="brand">TrustGate <span class="tag">통합인증 IdP</span></div></div>
<main class="narrow">
  <div class="card">
    <h1>로그아웃할까요?</h1>
    <p class="sub">TrustGate 통합인증 세션을 끝내면, 이 세션으로 로그인한 모든 서비스에서 함께 로그아웃됩니다.</p>
    <form method="post" action="${pageContext.request.contextPath}/logout" class="row">
      <input type="hidden" name="csrf" value="${csrf}">
      <c:if test="${not empty clientId}"><input type="hidden" name="client_id" value="<c:out value='${clientId}'/>"></c:if>
      <c:if test="${not empty postLogoutRedirectUri}"><input type="hidden" name="post_logout_redirect_uri" value="<c:out value='${postLogoutRedirectUri}'/>"></c:if>
      <button>로그아웃</button>
      <a class="btn ghost" href="${pageContext.request.contextPath}/">취소</a>
    </form>
  </div>
</main>
</body>
</html>
