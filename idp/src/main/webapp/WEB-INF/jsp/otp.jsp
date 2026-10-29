<%@ include file="header.jspf" %>
<c:set var="title" value="2차 인증"/>
<%@ include file="head.jspf" %>
<body>
<div class="top"><div class="brand">TrustGate <span class="tag">통합인증 IdP</span></div></div>
<main class="narrow">
  <div class="card">
    <h1>2차 인증 (OTP)</h1>
    <p class="sub"><b><c:out value="${username}"/></b> 계정의 인증 앱(Google Authenticator 등)에 표시된 6자리 코드를 입력하세요.</p>
    <c:if test="${not empty error}"><div class="alert error"><c:out value="${error}"/></div></c:if>
    <form method="post" action="${pageContext.request.contextPath}/otp" autocomplete="off">
      <input type="hidden" name="csrf" value="${csrf}">
      <label for="code">OTP 코드</label>
      <input type="text" id="code" name="code" class="otp" inputmode="numeric" maxlength="6" pattern="[0-9]{6}" required autofocus>
      <button type="submit" class="wide">인증</button>
    </form>
    <p class="muted" style="margin-top:14px">코드는 30초마다 바뀌고, 한 번 쓴 코드는 다시 쓸 수 없습니다.</p>
    <c:if test="${not empty demoCode}">
      <div class="demo">데모 모드 · 지금 유효한 코드: <code><c:out value="${demoCode}"/></code><br>
        실제 서비스에서는 이 표시가 없으며 TG_DEMO_MODE=false로 끕니다.</div>
    </c:if>
  </div>
</main>
</body>
</html>
