# SecureBit.chat Build Script
# PowerShell script for building the application

Write-Host "🔨 Building SecureBit.chat..." -ForegroundColor Green

# Check if Node.js is installed
if (!(Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Node.js is not installed. Please install Node.js first." -ForegroundColor Red
    exit 1
}

# Check if npm is installed
if (!(Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Host "❌ npm is not installed. Please install npm first." -ForegroundColor Red
    exit 1
}

# Install dependencies if needed
if (!(Test-Path "node_modules")) {
    Write-Host "📦 Installing dependencies..." -ForegroundColor Yellow
    npm install
}

# Install build tools if needed
Write-Host "🛠️  Installing build tools..." -ForegroundColor Yellow
npm install -D tailwindcss esbuild
npm install qrcode

# Create directories if they don't exist
if (!(Test-Path "dist")) { New-Item -ItemType Directory -Path "dist" }
if (!(Test-Path "assets")) { New-Item -ItemType Directory -Path "assets" }

# Build CSS
Write-Host "🎨 Building Tailwind CSS..." -ForegroundColor Cyan
try {
    npx tailwindcss -i src/styles/tw-input.css -o assets/tailwind.css --minify --content "./index.html,./src/**/*.jsx,./src/**/*.js"
    Write-Host "✅ CSS build completed" -ForegroundColor Green
} catch {
    Write-Host "❌ CSS build failed: $_" -ForegroundColor Red
    exit 1
}

# Build JavaScript files
Write-Host "⚡ Building JavaScript files..." -ForegroundColor Cyan

# Build main app
try {
    npx esbuild src/app.jsx --bundle --format=esm --outfile=dist/app.js --sourcemap
    Write-Host "✅ Main app build completed" -ForegroundColor Green
} catch {
    Write-Host "❌ Main app build failed: $_" -ForegroundColor Red
    exit 1
}

# Build app bootstrap
try {
    npx esbuild src/scripts/app-boot.js --bundle --format=esm --outfile=dist/app-boot.js --sourcemap
    Write-Host "✅ App bootstrap build completed" -ForegroundColor Green
} catch {
    Write-Host "❌ App bootstrap build failed: $_" -ForegroundColor Red
    exit 1
}

# Build QR generator
try {
    npx esbuild src/scripts/qr-local.js --bundle --format=esm --outfile=dist/qr-local.js --sourcemap
    Write-Host "✅ QR generator build completed" -ForegroundColor Green
} catch {
    Write-Host "❌ QR generator build failed: $_" -ForegroundColor Red
    exit 1
}

Write-Host "🎉 Build completed successfully!" -ForegroundColor Green
Write-Host "📁 Output files:" -ForegroundColor Yellow
Write-Host "   - assets/tailwind.css" -ForegroundColor White
Write-Host "   - dist/app.js" -ForegroundColor White
Write-Host "   - dist/app-boot.js" -ForegroundColor White
Write-Host "   - dist/qr-local.js" -ForegroundColor White

Write-Host "`n🚀 You can now serve the application with:" -ForegroundColor Cyan
Write-Host "   python -m http.server 8000" -ForegroundColor White
Write-Host "   or" -ForegroundColor White
Write-Host "   npx http-server" -ForegroundColor White
