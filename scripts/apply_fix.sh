#!/bin/bash

# =============================================================
# apply_fix.sh
# Risk_Report.csv를 기반으로 Apache TLS 취약 설정을 자동 교정
# 실행 전 원본 설정 파일을 자동 백업하여 롤백 가능하도록 설계
# =============================================================

# 주요 파일 경로 변수 정의
RISK_FILE="/opt/testssl/Risk_Report.csv"								                # testssl_analyzer.sh가 생성한 취약 항목 분석 결과 파일
APACHE_SSL_CONF="/etc/apache2/sites-available/default-ssl.conf"			    # Apache SSL 설정 파일(교정 대상)
SECURITY_CONF="/etc/apache2/conf-available/security.conf"				        # Apache 보안 설정 파일
BACKUP_FILE="/etc/apache2/mods-available/ssl.conf.bak.$(date +%F_%T)"	  # 교정 전 원본 설정 파일 백업 경로(날짜, 시간 포함)

# 1. 설정 파일 백업

# 교정 전 원본 Apache SSL 설정 파일을 백업
# 오류 발생 시 백업 파일로 롤백 가능

echo "[*] BackUP: $BACKUP_FILE"
sudo cp "$APACHE_SSL_CONF" "$BACKUP_FILE"

# 2. 설정 삽입 기준 위치 탐색

# SSLCertificateKeyFile 라인 번호를 탐색하여 삽입 기준점으로 사용
# SSL 블록 내에서 SSLCertificateKeyFile 바로 아래에 보안 설정을 삽입하는 것이 일반적
# 해당 라인을 찾지 못하면 스크립트 종료

insert_line=$(awk '
  BEGIN { ssl_block = 0; found = 0; insert_after = 0; }
  /SSL Engine Switch:/ { ssl_block = 1 }
  ssl_block && /SSLCertificateKeyFile/ {
    print NR; found = 1; ssl_block = 0; exit
  }
' "$APACHE_SSL_CONF")

if [[ -z "$insert_line" ]]; then
  echo "[!] Could not locate SSLCertificateKeyFile line. Exiting."
  exit 1
fi

# 3. TLS 1.2 / 1.3 활성화

# Risk_Report.csv에서 TLS 1.2 또는 1.3이 미지원으로 분류된 경우, Apache 설정 파일에서 해당 프로토콜 비활성화 구문을 주석 처리하여 활성화

secure_protocols=("TLS1_2" "TLS1_3")
activated_protocols=()

for proto in "${secure_protocols[@]}"; do
  if grep -qiE "$proto: not offered" "$RISK_FILE"; then
    if [[ "$proto" == "TLS1_2" ]]; then
      variant=('TLSv1.2' 'TLS1_2')
      proto_str='TLSv1.2'
    elif [[ "$proto" == "TLS1_3" ]]; then
      variant=('TLSv1.3' 'TLS1_3')
      proto_str='TLSv1.3'
    fi

    for variant in "${variant[@]}"; do
    if grep -q "Protocol \"-$variant\"" "$APACHE_SSL_CONF"; then
      sudo sed -i -E "s/^(.*Protocol \"-$variant\".*)/# \1/" "$APACHE_SSL_CONF"
      activated_protocols+=("$proto_str")
    fi
  done
  fi
done

if [[ ${#activated_protocols[@]} -gt 0 ]]; then
  for proto in "${activated_protocols[@]}"; do
    echo "[+] $proto: not offered"
  done
else
  echo "[+] TLS 1.2 and 1.3 are already offered."
fi

# 4. 암호 스위트 교정

# 기존 SSLCipherSuite 설정을 주석 처리하고 안전한 암호 스위트를 삽입
# aNULL: 인증 없는 암호화 제외

CIPHER_LINE="SSLCipherSuite HIGH:!aNULL:!MD5:!SHA1:!3DES"
if grep -q "SSLCipherSuite" "$APACHE_SSL_CONF"; then
  sudo sed -i -E 's/^(\s*)SSLCipherSuite(\s+.*)/# \1SSLCipherSuite\2/' "$APACHE_SSL_CONF"
fi

if ! grep -qF "$CIPHER_LINE" "$APACHE_SSL_CONF"; then
  sudo sed -i "$((insert_line+1))i $CIPHER_LINE" "$APACHE_SSL_CONF"
  echo "[+] SSLCipherSuite Applied"
fi

# 5. DH 파라미터 적용

# Diffie-Hellman 파라미터 파일이 없으면 2048bit로 생성
# DH 파라미터 강화로 키 교환 시 전방향 안전성(Forward Secrecy) 확보
# 이미 설정되어 있지 않은 경우에만 Apache 설정 파일에 삽입

DH_FILE="/etc/ssl/certs/dhparam.pem"
DH_LINE='SSLOpenSSLConfCmd DHParameters "/etc/ssl/certs/dhparam.pem"'

if [[ ! -f "$DH_FILE" ]]; then
  echo "[*] Generating DH parameters (2048-bit)..."
  sudo openssl dhparam -out "$DH_FILE" 2048
fi

if ! grep -q "$DH_LINE" "$APACHE_SSL_CONF"; then
  sudo sed -i "$((insert_line+2))i $DH_LINE" "$APACHE_SSL_CONF"
  echo "[+] DH Parameters Applied"
fi

# 6. mod_headers 모듈 활성화

# HSTS 헤더 삽입을 위해 Apache mod_headers 모듈 활성화 필요

if ! a2query -m headers | grep -q "enabled"; then  
  echo "[*] mod_headers activating"
  sudo a2enmod headers
  echo "[+] mod_headers activation complete"
else
  echo "[+] mod_headers already enabled"
fi

# 7. HSTS 헤더 삽입

# HTTP Strict Transport Security(HSTS) 헤더 적용
# max-age=31536000: 1년간 HTTPS 강제 사용
# includeSubDomains: 서브 도메인에도 동일하게 적용
# 중간자 공격(MITM) 방지 및 HTTP 다운그레이드 공격 차단

HSTS_LINE='Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"'
if ! grep -q "Strict-Transport-Security" "$APACHE_SSL_CONF"; then
  echo "[*] HSTS settings adding"
  sudo sed -i "/<\/VirtualHost>/i $HSTS_LINE" "$APACHE_SSL_CONF"
  echo "[+] HSTS header addition completed"
else
  echo "[+] HSTS already enabled"
fi

# 8. 서버 배너 숨김

# 서버 버전 정보 노출 차단
# ServerTokens Prod: 응답 헤더에 "Apache"만 표시 (버전 정보 제거)
# ServerSignature Off: 오류 페이지 하단 서버 정보 표시 금지
# 설정이 없는 경우 파일 끝에 추가

if [[ -f "$SECURITY_CONF" ]]; then
  echo "[*] Setting up server banner hide"
  sudo sed -i 's/^ServerTokens .*/ServerTokens Prod/' "$SECURITY_CONF"
  sudo sed -i 's/^ServerSignature .*/ServerSignature Off/' "$SECURITY_CONF"

  # Add if you don't have it
  grep -q "^ServerTokens" "$SECURITY_CONF" || echo "ServerTokens Prod" | sudo tee -a "$SECURITY_CONF" > /dev/null
  grep -q "^ServerSignature" "$SECURITY_CONF" || echo "ServerSignature Off" | sudo tee -a "$SECURITY_CONF" > /dev/null

  echo "[+] Server banner setup complete"
fi

# 9. 서버 암호 우선순위 적용

# SSLHonorCipherOrder on 설정으로 서버가 정의한 암호 스위트 순서 강제 적용
# 클라이언트가 취약한 암호 스위트를 선택하는 것을 방지

if grep -q "^SSLHonorCipherOrder" "$APACHE_SSL_CONF"; then
  sudo sed -i 's/^.*SSLHonorCipherOrder.*/SSLHonorCipherOrder on/' "$APACHE_SSL_CONF"
else
  sudo sed -i "$((insert_line+3))i SSLHonorCipherOrder on" "$APACHE_SSL_CONF"
fi
echo "[+] SSLHonorCipherOrder on Applied"
