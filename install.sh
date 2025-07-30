#!/bin/bash

# blackmirror Installation Script

echo "🔥 Installing blackmirror..."
echo "================================"

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    echo "Please install Python 3.8 or higher and try again."
    exit 1
fi

# Check Python version
python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Python 3.8 or higher is required. Found: $python_version"
    exit 1
fi

echo "✅ Python $python_version detected"

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip3 install -r requirements.txt

if [ $? -ne 0 ]; then
    echo "❌ Failed to install Python dependencies"
    exit 1
fi

echo "✅ Python dependencies installed"

# Check for external tools
echo "🔧 Checking external tools..."

# Check nmap
if ! command -v nmap &> /dev/null; then
    echo "⚠️  nmap not found. Installing..."
    if command -v apt &> /dev/null; then
        sudo apt update && sudo apt install -y nmap
    elif command -v yum &> /dev/null; then
        sudo yum install -y nmap
    elif command -v brew &> /dev/null; then
        brew install nmap
    else
        echo "❌ Could not install nmap automatically. Please install it manually."
        echo "   Ubuntu/Debian: sudo apt install nmap"
        echo "   CentOS/RHEL: sudo yum install nmap"
        echo "   macOS: brew install nmap"
    fi
else
    echo "✅ nmap found"
fi

# Check nuclei
if ! command -v nuclei &> /dev/null; then
    echo "⚠️  nuclei not found. Installing..."
    if command -v go &> /dev/null; then
        go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
        echo "✅ nuclei installed via Go"
    else
        echo "⚠️  Go not found. Please install nuclei manually:"
        echo "   go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
    fi
else
    echo "✅ nuclei found"
fi

# Make scripts executable
chmod +x blackmirror.py
chmod +x test_blackmirror.py

echo "✅ Scripts made executable"

# Run test suite
echo "🧪 Running test suite..."
python3 test_blackmirror.py

if [ $? -eq 0 ]; then
    echo ""
    echo "🎉 Installation completed successfully!"
    echo ""
    echo "Usage examples:"
    echo "  python3 blackmirror.py example.com"
    echo "  python3 blackmirror.py 192.168.1.10 --ports --web"
    echo "  python3 blackmirror.py example.com --export markdown"
    echo ""
    echo "For more information, see README.md"
else
    echo ""
    echo "⚠️  Installation completed with warnings."
    echo "Some features may not work properly."
    echo "Please check the test output above."
fi 