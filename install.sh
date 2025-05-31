#!/bin/bash

set -e

echo "Installing scango-lite..."
curl -L -o scango https://raw.githubusercontent.com/vichekaoeun/scango-lite/main/scango
chmod +x scango

if [ -w /usr/local/bin ]; then
    mv scango /usr/local/bin/
    echo "✅ scango installed to /usr/local/bin/scango"
else
    sudo mv scango /usr/local/bin/
    echo "✅ scango installed to /usr/local/bin/scango"
fi

echo "Try: scango run"