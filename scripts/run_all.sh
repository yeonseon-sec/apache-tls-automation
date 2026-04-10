#!/bin/bash

# =============================================================
# run_all.sh
# apply_fix.sh 실행 후 Apache를 자동 재시작하는 통합 실행 스크립트
# 단일 명령어(bash run_all.sh)로 교정부터 재시작까지 일괄 처리
# =============================================================

# 작업 디렉토리 이동
# apply_fix.sh와 Risk_Report.csv가 위치한 디렉토리로 이동
# 이동 실패 시 즉시 종료

WORK_DIR="/opt/testssl"
cd "$WORK_DIR" || exit 1


# 1. apply_fix.sh에 실행 권한을 부여하고 실행

# chmod +x: 실행 권한이 없는 경우를 대비한 사전 처리
# apply_fix.sh: Risk_Report.csv 기반으로 Apache TLS 설정을 자동 교정

chmod +x apply_fix.sh
./apply_fix.sh


# 2. 변경된 Apache 설정을 적용하기 위해 서비스 재시작

sudo systemctl reload apache2
echo "Completed"
