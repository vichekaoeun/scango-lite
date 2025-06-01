#!/bin/bash

set -e

echo "🔍 Installing scango-lite security scanner..."
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go 1.21+ first:"
    echo "   https://golang.org/downloads/"
    exit 1
fi

# Check Go version
GO_VERSION=$(go version | cut -d' ' -f3 | sed 's/go//')
echo "✅ Found Go $GO_VERSION"

# Install scango-lite
echo "📦 Installing scango-lite..."
go install github.com/vichekaoeun/scango-lite@latest

echo ""
echo "🎉 Installation complete!"
echo ""
echo "Usage:"
echo "  scango-lite run     # Scan current directory"
echo "  scango-lite help    # Show help"
echo "  scango-lite bench   # Performance benchmark"
echo ""
echo "Try it now: scango-lite run"