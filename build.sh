#!/bin/bash

echo "开始构建 Hellokit 文件加解密工具..."

# 检查Go是否安装
if ! command -v go &> /dev/null; then
    echo "错误: 未找到Go，请先安装Go"
    exit 1
fi

# 安装依赖
echo "安装依赖..."
go mod tidy

# 构建程序
echo "构建程序..."
go build -o filecrypt main.go crypto.go

if [ $? -eq 0 ]; then
    echo "构建成功!"
    echo "可执行文件: ./filecrypt"
    echo ""
    echo "使用示例:"
    echo "  ./filecrypt encrypt -i input.txt -o encrypted.hke -p password"
    echo "  ./filecrypt decrypt -i encrypted.hke -o decrypted.txt -p password"
    echo "  ./filecrypt info -i encrypted.hke"
else
    echo "构建失败!"
    exit 1
fi 