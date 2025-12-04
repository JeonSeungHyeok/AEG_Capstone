#!/bin/bash

echo "[*] 시스템 패키지 업데이트 및 설치 중..."
sudo apt-get update
sudo apt-get install -y build-essential clang llvm g++-multilib libc6-dev-i386 python3-pip python3-venv gcc-multilib g++ 

echo "[*] Python 가상환경(venv) 생성 중..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "    -> venv 생성 완료"
else
    echo "    -> venv가 이미 존재합니다."
fi

echo "[*] 가상환경 활성화 및 Python 패키지 설치 중..."
source venv/bin/activate
pip install --upgrade pip
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    echo "    -> Python 패키지 설치 완료"
else
    echo "    [!] requirements.txt 파일이 없습니다."
fi

echo "=========================================="
echo " 환경 설정이 완료되었습니다."
echo " 'source venv/bin/activate' 를 입력하여 작업을 시작하세요."
echo "=========================================="
