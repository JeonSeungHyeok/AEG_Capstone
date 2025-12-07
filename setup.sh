#!/bin/bash

echo "[*] Updating and installing system packages..."
sudo apt-get update
sudo apt-get install -y build-essential clang llvm g++-multilib libc6-dev-i386 python3-pip python3-venv gcc-multilib g++ 

echo "[*] Creating Python virtual environment (venv)..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "venv created successfully."
else
    echo "    -> venv already exists."
fi

echo "[*] Activating virtual environment and installing Python packages..."
source venv/bin/activate
pip install --upgrade pip
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    echo "    -> Python packages installed successfully."
else
    echo "    [!] requirements.txt not found."
fi

echo "=========================================="
echo " Environment setup complete."
echo " Run 'source venv/bin/activate' to start working."
echo "=========================================="
