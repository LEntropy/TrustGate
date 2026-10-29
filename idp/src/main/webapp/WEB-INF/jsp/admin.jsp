<%@ include file="header.jspf" %>
<c:set var="title" value="보안 관리 콘솔"/>
<%@ include file="head.jspf" %>
<body>
<div class="top">
  <div class="brand">TrustGate <span class="tag">보안 관리 콘솔</span></div>
  <nav>
    <a href="${pageContext.request.contextPath}/">내 계정</a>
    <a href="${pageContext.request.contextPath}/logout">로그아웃</a>
  </nav>
</div>
<main>
  <c:if test="${not empty flash}"><div class="alert ok"><c:out value="${flash}"/></div></c:if>

  <div class="card">
    <h1>사용자와 암호화된 개인정보</h1>
    <p class="sub">DB에 실제로 저장된 값(암호문)과, 복호화 후 마스킹해 보여주는 값을 나란히 표시합니다. 저장소: <c:out value="${dbProduct}"/></p>
    <div class="tablewrap">
      <table>
        <tr><th>ID</th><th>아이디</th><th>이름</th><th>주민등록번호 (마스킹)</th><th>RRN_ENC (DB 저장값)</th>
          <th>RRN_IDX (블라인드 인덱스)</th><th>키</th><th>OTP</th><th>상태</th><th></th></tr>
        <c:forEach var="r" items="${rows}">
          <tr>
            <td><c:out value="${r.id()}"/></td>
            <td><c:out value="${r.username()}"/><br><span class="muted"><c:out value="${r.role()}"/></span></td>
            <td><c:out value="${r.name()}"/></td>
            <td><c:out value="${r.rrnMasked()}"/><br><span class="muted"><c:out value="${r.phoneMasked()}"/></span></td>
            <td class="cipher" style="max-width:260px"><c:out value="${r.rrnEnc()}"/></td>
            <td class="cipher" style="max-width:160px"><c:out value="${r.rrnIdx()}"/></td>
            <td><span class="pill ${r.rrnKeyVersion() == activeVersion ? 'ok' : 'warn'}">v<c:out value="${r.rrnKeyVersion()}"/></span></td>
            <td><c:out value="${r.otp() ? '등록' : '미등록'}"/></td>
            <td><c:if test="${r.locked()}"><span class="pill bad">잠김</span></c:if></td>
            <td style="white-space:nowrap">
              <form class="inline-form" method="post" action="${pageContext.request.contextPath}/admin">
                <input type="hidden" name="csrf" value="${csrf}"><input type="hidden" name="id" value="${r.id()}">
                <button class="small ghost" name="action" value="resetOtp">OTP 초기화</button>
                <c:if test="${r.locked()}"><button class="small ghost" name="action" value="unlock">잠금 해제</button></c:if>
              </form>
            </td>
          </tr>
        </c:forEach>
      </table>
    </div>
  </div>

  <div class="grid2">
    <div class="card">
      <h2>키 관리 (Envelope Encryption)</h2>
      <p class="muted">KEK: <c:out value="${kek}"/></p>
      <table>
        <tr><th>용도</th><th>버전</th><th>상태</th><th>생성</th></tr>
        <c:forEach var="k" items="${keys}">
          <tr>
            <td><c:out value="${k.purpose() == 'ENC' ? '데이터 암호화' : '블라인드 인덱스'}"/></td>
            <td>v<c:out value="${k.version()}"/></td>
            <td><span class="pill ${k.status() == 'ACTIVE' ? 'ok' : 'warn'}"><c:out value="${k.status()}"/></span></td>
            <td class="muted"><c:out value="${k.createdAt()}"/></td>
          </tr>
        </c:forEach>
      </table>
      <p class="muted" style="margin-top:12px">키 버전별 암호화된 값 수:
        <c:forEach var="e" items="${perVersion}"> v<c:out value="${e.key}"/> = <c:out value="${e.value}"/>개 </c:forEach></p>
      <form method="post" action="${pageContext.request.contextPath}/admin" class="row">
        <input type="hidden" name="csrf" value="${csrf}">
        <button name="action" value="rotate">1. 데이터 키 교체</button>
        <button name="action" value="reencrypt" class="ghost">2. 활성 키로 재암호화</button>
      </form>
    </div>

    <div class="card">
      <h2>암호화된 컬럼 검색</h2>
      <p class="muted">주민등록번호는 매번 다른 암호문이 되므로 그대로는 검색할 수 없습니다. 별도 키로 만든 HMAC 값(블라인드 인덱스)으로 일치 여부만 찾습니다.</p>
      <form method="post" action="${pageContext.request.contextPath}/admin" autocomplete="off">
        <input type="hidden" name="csrf" value="${csrf}">
        <label for="rrn">주민등록번호</label>
        <input type="text" id="rrn" name="rrn" placeholder="900101-1234567">
        <button name="action" value="search" class="wide">검색</button>
      </form>
      <c:if test="${not empty searchError}"><div class="alert error" style="margin-top:12px"><c:out value="${searchError}"/></div></c:if>
      <c:if test="${not empty searchResult}">
        <div class="alert info" style="margin-top:12px">결과: <c:out value="${searchResult}"/><br>
          <span class="cipher">검색 토큰 RRN_IDX = <c:out value="${searchToken}"/></span></div>
      </c:if>
    </div>
  </div>

  <div class="card">
    <h2>사용자 추가</h2>
    <form method="post" action="${pageContext.request.contextPath}/admin" autocomplete="off">
      <input type="hidden" name="csrf" value="${csrf}">
      <div class="row">
        <div><label for="nu">아이디</label><input type="text" id="nu" name="username" placeholder="user3"></div>
        <div><label for="nn">이름</label><input type="text" id="nn" name="name"></div>
        <div><label for="np">비밀번호 (8자 이상)</label><input type="password" id="np" name="password"></div>
        <div><label for="nr">주민등록번호</label><input type="text" id="nr" name="rrn"></div>
        <div><label for="nph">휴대폰</label><input type="text" id="nph" name="phone"></div>
        <div style="flex:0 0 auto"><button name="action" value="create">추가</button></div>
      </div>
    </form>
  </div>

  <div class="card">
    <h2>감사 로그 (최근 40건)</h2>
    <div class="tablewrap">
      <table>
        <tr><th>시각 (UTC)</th><th>사용자</th><th>이벤트</th><th>내용</th><th>IP</th></tr>
        <c:forEach var="a" items="${audit}">
          <tr>
            <td class="muted" style="white-space:nowrap"><c:out value="${a.ts()}"/></td>
            <td><c:out value="${a.username()}"/></td>
            <td><span class="pill ${a.event().contains('FAIL') || a.event().contains('LOCK') || a.event().contains('REJECT') || a.event().contains('DENIED') || a.event().contains('REPLAY') ? 'bad' : 'info'}"><c:out value="${a.event()}"/></span></td>
            <td class="mono"><c:out value="${a.detail()}"/></td>
            <td class="muted"><c:out value="${a.ip()}"/></td>
          </tr>
        </c:forEach>
      </table>
    </div>
  </div>
</main>
</body>
</html>
