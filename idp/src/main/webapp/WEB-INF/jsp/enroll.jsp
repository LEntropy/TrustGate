<%@ include file="header.jspf" %>
<c:set var="title" value="OTP 등록"/>
<%@ include file="head.jspf" %>
<body>
<div class="top"><div class="brand">TrustGate <span class="tag">통합인증 IdP</span></div></div>
<main style="max-width:620px">
  <div class="card">
    <h1>OTP 등록</h1>
    <p class="sub"><b><c:out value="${username}"/></b> 계정은 아직 2차 인증이 등록되지 않았습니다. 처음 한 번만 등록하면 됩니다.</p>
    <c:if test="${not empty error}"><div class="alert error"><c:out value="${error}"/></div></c:if>
    <div class="qr">
      <img src="${qr}" alt="OTP 등록 QR 코드">
      <div>
        <ol class="steps">
          <li>휴대폰에서 Google Authenticator 또는 Microsoft Authenticator를 엽니다.</li>
          <li>QR 코드를 스캔합니다. 스캔이 안 되면 아래 키를 직접 입력합니다.</li>
          <li>앱에 표시된 6자리 코드를 입력합니다.</li>
        </ol>
        <label>설정 키 (Base32)</label>
        <div class="secret"><c:out value="${secret}"/></div>
      </div>
    </div>
    <form method="post" action="${pageContext.request.contextPath}/otp/enroll" autocomplete="off">
      <input type="hidden" name="csrf" value="${csrf}">
      <label for="code">앱에 표시된 코드</label>
      <input type="text" id="code" name="code" class="otp" inputmode="numeric" maxlength="6" pattern="[0-9]{6}" required autofocus>
      <button type="submit" class="wide">등록하고 로그인</button>
    </form>
    <p class="muted" style="margin-top:14px">코드가 맞아야 등록됩니다. 등록된 키는 AES-256-GCM으로 암호화되어 DB에 저장됩니다.</p>
    <c:if test="${not empty demoCode}">
      <div class="demo">데모 모드 · 이 키로 지금 계산된 코드: <code><c:out value="${demoCode}"/></code></div>
    </c:if>
  </div>
</main>
</body>
</html>
