# Apache TLS 보안 구성 진단 및 자동화 스크립트

## 프로젝트 배경

Apache 웹 서버의 TLS 설정을 수동으로 점검할 경우 인적 오류와 시간 소요가 크다는 문제의식에서 출발했습니다.
취약한 항목을 자동으로 진단하고 교정하여 보안 설정의 일관성과 신뢰성을 높이는 것을 목표로 했습니다.

## 프로젝트 개요

Apache 웹 서버의 TLS 설정을 점검하고 취약하거나 비권장된 보안 설정을 안전한 설정으로 자동화하는 스크립트를 제작하는 것입니다.

## 사용 환경

- 웹 서버: Ubuntu 22 (Apache 2.4.52)
- 진단 서버: Kali linux 2024.4
- 가상화 도구: VMware Workstation
- 진단 도구: testssl.sh (외부 오픈소스 TLS 진단 도구)
- 언어: Bash shell script  

testssl.sh를 선택한 이유는 OpenSSL과 Nmap이 개별 항목 확인에는 유용하지만 다양한 항목을 통합적으로 분석하기에는 한계가 있기 때문입니다.  
testssl.sh는 TLS 구성 요소를 한 번에 점검하고 취약 여부를 체계적으로 분류하여 제공하기 때문에 자동화된 분석과 후속 교정에 적합하다고 판단했습니다.

## 네트워크 구성도

실제 기업 환경에서는 서비스 영향을 최소화하기 위해 보안 점검 시스템과 운영 서버를 분리하여 점검을 수행하는 구조를 권장합니다.  
본 프로젝트에서도 이러한 구조를 참고하여 진단 서버(Kali Linux)와 웹 서버(Apache)를 분리된 시스템으로 구성하였습니다.
두 시스템은 동일한 사설 네트워크 내에 배치하여 외부 영향 없이 내부 환경에서 TLS 진단이 수행되도록 설계하였습니다.
이를 통해 실제 서비스 환경과 유사하게 서버 간 통신 구조를 유지하면서 테스트 과정에서 발생할 수 있는 설정 변경이나 부하가 외부 서비스에 영향을 주지 않도록 하였습니다.  

```
[Kali Linux(진단 서버)]               [Apache Web Server(웹 서버)]
- TLS 진단 수행 (testssl.sh)          - 취약한 TLS 설정 적용
- 웹 접속 테스트 (Firefox)            - 자동화 스크립트 실행 대상
                     ⟵ HTTPS, Port 443 ⟶
```
아래는 Kali Firefox에서 실제 HTTPS 접속을 확인한 화면입니다.
자체 서명 인증서로 인한 브라우저 보안 경고 화면이 표시됩니다.

<img width="850" src="https://github.com/user-attachments/assets/6c0806b3-a6c8-414f-913b-87d87196d492" />

## 진단 항목

본 프로젝트의 TLS 설정 자동화 기준은 다음을 기반으로 정의했습니다.  

- testssl.sh 진단 결과에서 취약으로 분류된 항목
- KISA, '암호 알고리즘 및 키 길이 이용 안내서'
- 개인정보보호협회, '2019년 권장 알고리즘 및 TLS 1.2 설정 가이드'

| 항목 | 점검 내용 |
|---|---|
| Protocol | TLS 1.3 지원 여부 |
| Cipher Suite | 안전한 암호 스위트 사용 여부, AEAD·FS 지원 여부 |
| Key Size | 안전한 인증서 공개키 알고리즘 키 길이 사용 여부, 안전한 키 교환 알고리즘 사용 여부 |
| HTTP Headers | HTTPS 적용, 서버 정보 노출 여부 |
| Server Cipher Order | 서버 우선순위 적용 여부 |

## 수행 과정

전체 흐름은 진단 → 분석 → 교정 → 검증 순서로 동작합니다.

```
testssl.sh 진단
      ↓
result.json 저장
      ↓
testssl_analyzer.sh 분석
      ↓
Risk_Report.csv 저장
      ↓
apply_fix.sh  (run_all.sh로 실행)
      ↓
Apache 재시작
      ↓
testssl.sh 재진단(검증)
```

각 스크립트의 역할은 다음과 같습니다.
| 스크립트 | 역할 |
|---|---|
| testssl_analyzer.sh| testssl.sh의 JSON 결과를 읽어 항목별로 취약 여부를 분류하고 Risk_Report.csv로 저장 |
| apply_fix.sh | Risk_Report.csv를 기반으로 Apache 설정 파일을 안전한 구성으로 자동 교정  |
| run_all.sh | apply_fix.sh 실행 후 Apache 자동 재시작, 단일 명령어(`bash run_all.sh`)로 일괄 처리 |  

### 1. 취약 환경 구성  

Apache 웹 서버에 의도적으로 취약한 TLS 설정을 적용하여 진단 대상 환경을 구성했습니다.    

- 비권장 암호 스위트 적용: `SSLCipherSuite AES256-SHA:AES128-SHA:DES-CBC-SHA`
- TLS 1.3 비활성화: `SSLOpenSSLConfCmd Protocol "-TLSv1.3"`  

취약 환경을 의도적으로 구성한 이유는 진단 도구가 실제로 취약점을 탐지하는지 검증하고 자동화 스크립트 적용 전후 결과를 명확하게 비교하기 위해서입니다. 

### 2. 1차 진단(취약점 식별)     

진단 서버(Kali)에서 testssl.sh를 실행하여 웹 서버의 TLS 구성을 점검했습니다.

```bash
./testssl.sh https://<WEB_SERVER_IP> # 진단 서버(Kali)에서 실행
```

진단 결과는 JSON 파일로 저장하여 이후 분석 스크립트의 입력값으로 활용했습니다.

<img width="400" src="https://github.com/user-attachments/assets/cbf82164-c999-419b-848a-a2ae98dafaef" />    
<img width="400" src="https://github.com/user-attachments/assets/bad4f81d-9e3f-4835-9439-dd083961440e" />

**1차 진단에서 발견된 취약점**  

| 항목 | 진단 결과 | 문제점 |
|---|---|---|
| Protocol | TLS 1.3 not offered | 최신 프로토콜 미지원, 하위 버전으로 다운그레이드 |
| Cipher Suite | CBC 모드 사용, FS 미지원 | 전방향 안전성(Forward Secrecy) 미적용, 취약한 암호화 방식 사용 |
| Key Size | Static RSA(2048) | 키 교환 시 전방향 안전성 미보장 |
| HTTP Headers | HTTPS미적용, 서버 정보 노출 | 중간자 공격 가능, 서버 정보 노출 |
| Server Cipher Order | 서버 우선순위 미적용 | 클라이언트가 취약한 암호 스위트 선택 가능 |

### 3. 취약점 분석

testssl_analyzer.sh를 실행하여 1차 진단 결과를 항목별로 분류하고 위험도를 분석했습니다.  

```bash
bash testssl_analyzer.sh # 진단 서버(Kali)에서 실행
```

분석 결과는 Risk_Report.csv로 저장되며 이 파일이 자동화 스크립트(apply_fix.sh)의 입력값으로 사용됩니다.   

### 4. 자동화 교정 적용    

run_all.sh를 실행하여 취약 항목을 자동으로 교정하고 Apache를 재시작했습니다.    
설정 변경 전 원본 파일을 자동 백업하여 오류 발생 시 롤백이 가능하도록 설계했습니다.  

```bash
bash run_all.sh # 웹 서버(Ubuntu)에서 실행
```

apply_fix.sh는 Risk_Report.csv를 읽어 항목별로 아래와 같이 Apache 설정을 자동 교정합니다.  

| 항목 | 교정 내용 |
|---|---|
| Protocol | TLS 1.2/1.3 비활성화 설정 주석 처리로 활성화 |
| Cipher Suite | 취약 설정 주석 처리 후 HIGH:!aNULL:!MD5:!SHA1:!3DES 적용 |
| Key Size | DH 파라미터 2048bit 생성 및 적용 |
| HTTP Headers | mod_headers 활성화 후 HSTS 헤더 삽입 (max-age=31536000; includeSubDomains) |
| Server Info | ServerTokens Prod, ServerSignature Off 적용 |
| Server Cipher Order | SSLHonorCipherOrder on 적용 |  

<img width="650" src="https://github.com/user-attachments/assets/bc487f82-08c6-40a4-9225-0a0fbc989f75" />

### 5. 2차 진단(검증)  

1차 진단과 동일한 방법으로 재진단하여 자동화 결과를 검증했습니다.  

```bash
./testssl.sh https://<WEB_SERVER_IP> # 진단 서버(Kali)에서 실행
```

2차 진단 결과는 아래 자동화 전후 결과 섹션에서 1차 진단과 비교하여 확인할 수 있습니다.

## 실행 방법
**1. 진단 실행** (진단 서버 Kali에서 실행)  

```bash
./testssl.sh https://<WEB_SERVER_IP>
```

진단 결과는 'result.json'으로 저장됩니다.

**2. 결과 분석** (진단 서버 Kali에서 실행)  

```bash
bash testssl_analyzer.sh
```

분석 결과는 'Risk_Report.csv'로 저장됩니다.

**3. 자동 교정 및 Apache 재시작** (웹 서버 Ubuntu에서 실행)  

스크립트 파일이 위치한 디렉토리(/opt/testssl)에서 실행합니다.  

```bash
bash run_all.sh
```

'Risk_Report.csv'를 기반으로 Apache 설정을 자동 교정하고 재시작합니다.

## 자동화 전후 결과  

자동화 교정 적용 전후 testssl.sh 진단 등급을 비교한 결과입니다.  
교정 전에는 TLS 1.3 미지원과 Forward Secrecy 미적용으로 인해 등급이 제한되었으나 교정 후 해당 경고가 해소되었습니다.  
단, 자체 서명 인증서 사용으로 인해 전체 등급은 T로 유지됩니다.  

<img width="650" src="https://github.com/user-attachments/assets/ffef458c-a953-4947-aa67-cbd0c26d884d" />

<p></p>

아래는 자동화 교정 전후 Apache 설정 파일의 변경 내용입니다.  
취약한 암호 스위트와 TLS 비활성화 설정이 주석 처리되고 안전한 설정이 자동으로 적용된 것을 확인할 수 있습니다.  

<p></p>

<img width="1000" src="https://github.com/user-attachments/assets/17a7303a-5ab2-40fd-adc8-eb3fb19dcdb5" />

<p></p>

| 항목 | 자동화 전 | 자동화 후 |
|---|---|---|
| Protocol | TLS 1.3 not offered | TLS 1.3 offered |
| Cipher Suite | CBC, FS 미지원 | AEAD·FS 지원 |
| Key Size | 키 교환(Static RSA(2048)) | 키 교환(DHE, ECDHE) |
| HSTS | 미적용 | 365일 강제 적용 |
| Server info | Apache 2.4.52 노출 | Apache만 표시 |
| 서버 우선순위 | 미적용 | 적용 |

## 한계점  

- 실습 환경 특성상 자체 서명 인증서 사용으로 브라우저 신뢰 체계 검증 미수행
- 다양한 Apache 버전 및 환경에 대한 범용성 부족
- 자동화 적용 시 환경별 설정 차이로 인한 오류 가능성 존재
- testssl.sh 사용에 따른 표준 도구(OpenSSL, Nmap) 대비 신뢰성 한계
- 원격 환경에서 설정 적용 시 권한 관리 문제 존재

## 개선 방향

- 실제 환경에서는 공인 인증서 적용
- 표준 도구와의 교차 검증 도입
- 환경별 설정 분기 처리 로직 추가
- 자동화 범위 축소 및 선택적 적용 방식 개선
- SSH 기반 인증 등 안전한 원격 접근 방식 적용
