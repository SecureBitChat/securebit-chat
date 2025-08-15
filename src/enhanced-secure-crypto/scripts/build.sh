#!/bin/bash
echo "🔧 Building Enhanced Secure Crypto WASM module..."

# Проверка wasm-pack
if ! command -v wasm-pack &> /dev/null; then
    echo "❌ wasm-pack not found. Installing..."
    curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
fi

# Сборка
echo "🚀 Building WASM module..."
wasm-pack build --target web --out-dir pkg --release

if [ $? -eq 0 ]; then
    echo "✅ Build completed successfully!"
    echo "📁 Generated files:"
    ls -la pkg/
else
    echo "❌ Build failed!"
    exit 1
fi