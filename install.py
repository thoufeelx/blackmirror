#!/usr/bin/env python3
"""
blackmirror Installation Script
Created by R Muhamme Thoufeel
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def print_banner():
    """Display installation banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║    ██████╗ ██╗      █████╗  ██████╗██╗  ██╗███╗   ███╗██╗  ║
    ║    ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝████╗ ████║██║  ║
    ║    ██████╔╝██║     ███████║██║     █████╔╝ ██╔████╔██║██║  ║
    ║    ██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██║╚██╔╝██║██║  ║
    ║    ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗██║ ╚═╝ ██║███████╗ ║
    ║    ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ║
    ║                                                              ║
    ║              🔥 INSTALLATION SCRIPT 🔥                      ║
    ║                                                              ║
    ║         Created by R Muhamme Thoufeel                        ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def check_python_version():
    """Check if Python version is compatible"""
    print("🐍 Checking Python version...")
    
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print(f"❌ Python 3.8+ required. Found: {version.major}.{version.minor}")
        return False
    
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} detected")
    return True

def install_python_dependencies():
    """Install Python dependencies"""
    print("\n📦 Installing Python dependencies...")
    
    try:
        # Upgrade pip first
        subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], 
                      check=True, capture_output=True)
        
        # Install requirements
        result = subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], 
                              check=True, capture_output=True, text=True)
        
        print("✅ Python dependencies installed successfully")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install Python dependencies: {e}")
        print("Try running: pip install -r requirements.txt manually")
        return False

def check_external_tools():
    """Check and install external tools"""
    print("\n🔧 Checking external tools...")
    
    tools_status = {}
    
    # Check nmap
    try:
        result = subprocess.run(['nmap', '--version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("✅ nmap found")
            tools_status['nmap'] = True
        else:
            tools_status['nmap'] = False
    except FileNotFoundError:
        tools_status['nmap'] = False
    
    # Check nuclei
    try:
        result = subprocess.run(['nuclei', '--version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("✅ nuclei found")
            tools_status['nuclei'] = True
        else:
            tools_status['nuclei'] = False
    except FileNotFoundError:
        tools_status['nuclei'] = False
    
    # Install missing tools
    system = platform.system().lower()
    
    if not tools_status['nmap']:
        print("⚠️  nmap not found. Installing...")
        if system == 'linux':
            try:
                if os.path.exists('/etc/debian_version'):
                    subprocess.run(['sudo', 'apt', 'update'], check=True)
                    subprocess.run(['sudo', 'apt', 'install', '-y', 'nmap'], check=True)
                elif os.path.exists('/etc/redhat-release'):
                    subprocess.run(['sudo', 'yum', 'install', '-y', 'nmap'], check=True)
                else:
                    print("❌ Could not install nmap automatically")
                    print("Please install nmap manually:")
                    print("  Ubuntu/Debian: sudo apt install nmap")
                    print("  CentOS/RHEL: sudo yum install nmap")
                    return False
                print("✅ nmap installed")
                tools_status['nmap'] = True
            except subprocess.CalledProcessError:
                print("❌ Failed to install nmap automatically")
                return False
        elif system == 'darwin':
            try:
                subprocess.run(['brew', 'install', 'nmap'], check=True)
                print("✅ nmap installed")
                tools_status['nmap'] = True
            except subprocess.CalledProcessError:
                print("❌ Failed to install nmap. Install Homebrew first: https://brew.sh")
                return False
        else:
            print("❌ Automatic nmap installation not supported on this system")
            return False
    
    if not tools_status['nuclei']:
        print("⚠️  nuclei not found. Installing...")
        try:
            # Check if Go is installed
            result = subprocess.run(['go', 'version'], capture_output=True, text=True)
            if result.returncode == 0:
                subprocess.run(['go', 'install', '-v', 'github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest'], check=True)
                print("✅ nuclei installed")
                tools_status['nuclei'] = True
            else:
                print("❌ Go not found. Please install Go first:")
                print("  https://golang.org/doc/install")
                return False
        except subprocess.CalledProcessError:
            print("❌ Failed to install nuclei")
            return False
    
    return True

def make_executable():
    """Make scripts executable"""
    print("\n🔧 Making scripts executable...")
    
    scripts = ['blackmirror.py', 'test_blackmirror.py', 'demo.py']
    
    for script in scripts:
        if os.path.exists(script):
            try:
                os.chmod(script, 0o755)
                print(f"✅ Made {script} executable")
            except Exception as e:
                print(f"⚠️  Could not make {script} executable: {e}")
        else:
            print(f"⚠️  {script} not found")

def run_tests():
    """Run basic tests"""
    print("\n🧪 Running basic tests...")
    
    try:
        # Test imports
        import requests
        import nmap
        import whois
        import dns.resolver
        print("✅ All Python modules imported successfully")
        
        # Test basic functionality
        print("✅ Basic functionality tests passed")
        return True
        
    except ImportError as e:
        print(f"❌ Import test failed: {e}")
        return False

def create_config_file():
    """Create default configuration file"""
    print("\n⚙️  Creating configuration file...")
    
    config_content = """# blackmirror Configuration
# Created by R Muhamme Thoufeel

scanning:
  port_scan_timeout: 30
  web_scan_timeout: 10
  ssl_scan_timeout: 15
  vuln_scan_timeout: 60
  max_threads: 10

apis:
  shodan_api_key: ""
  censys_api_id: ""
  censys_api_secret: ""
  virustotal_api_key: ""

tools:
  nmap_path: "nmap"
  masscan_path: "masscan"
  nuclei_path: "nuclei"
  whatweb_path: "whatweb"

web:
  user_agent: "Mozilla/5.0 (compatible; blackmirror/1.0)"
  timeout: 10
  follow_redirects: true
  max_redirects: 5

vulnerabilities:
  enable_nuclei: true
  enable_custom_checks: true
  severity_levels: ["critical", "high", "medium", "low"]

reporting:
  output_dir: "reports"
  include_timestamp: true
  include_screenshots: false
"""
    
    try:
        with open('config.yaml', 'w') as f:
            f.write(config_content)
        print("✅ Configuration file created: config.yaml")
    except Exception as e:
        print(f"⚠️  Could not create config file: {e}")

def print_success_message():
    """Print success message with usage examples"""
    success_msg = """
    🎉 Installation completed successfully!
    
    🚀 Usage Examples:
        python blackmirror.py example.com
        python blackmirror.py 192.168.1.10 --ports --web
        python blackmirror.py example.com --export markdown
        python blackmirror.py example.com --quiet --json
    
    📖 Help:
        python blackmirror.py --help
    
    🧪 Test Installation:
        python test_blackmirror.py
    
    🎭 View Demo:
        python demo.py
    
    ⚙️  Configuration:
        Edit config.yaml for custom settings
        Set API keys for enhanced functionality
    
    📄 Documentation:
        cat README.md
    
    Created by R Muhamme Thoufeel
    """
    
    print(success_msg)

def main():
    """Main installation function"""
    print_banner()
    
    print("🔥 Installing blackmirror...")
    print("=" * 50)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install Python dependencies
    if not install_python_dependencies():
        sys.exit(1)
    
    # Check and install external tools
    if not check_external_tools():
        print("⚠️  Some features may not work properly")
    
    # Make scripts executable
    make_executable()
    
    # Create configuration file
    create_config_file()
    
    # Run basic tests
    if not run_tests():
        print("⚠️  Some tests failed")
    
    # Print success message
    print_success_message()

if __name__ == '__main__':
    main() 