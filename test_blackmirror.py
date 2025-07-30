#!/usr/bin/env python3
"""
blackmirror Test Suite
Created by R Muhamme Thoufeel
"""

import sys
import os
import subprocess
import platform
from pathlib import Path
import socket

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def print_banner():
    """Display test suite banner"""
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
    ║              🔥 TEST SUITE 🔥                               ║
    ║                                                              ║
    ║         Created by R Muhamme Thoufeel                        ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def test_python_version():
    """Test Python version compatibility"""
    print("🐍 Testing Python version...")
    
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print(f"❌ Python 3.8+ required. Found: {version.major}.{version.minor}")
        return False
    
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} - Compatible")
    return True

def test_imports():
    """Test if all required modules can be imported"""
    print("\n📦 Testing Python imports...")
    
    modules = {
        'click': 'CLI interface',
        'requests': 'HTTP requests',
        'beautifulsoup4': 'HTML parsing',
        'nmap': 'Port scanning',
        'rich': 'Terminal formatting',
        'pyyaml': 'Configuration management',
        'whois': 'WHOIS lookups',
        'dns.resolver': 'DNS queries',
        'ssl': 'SSL/TLS support',
        'cryptography': 'Cryptographic functions'
    }
    
    failed_imports = []
    
    for module, description in modules.items():
        try:
            __import__(module)
            print(f"✅ {module} - {description}")
        except ImportError:
            print(f"❌ {module} - {description} (MISSING)")
            failed_imports.append(module)
    
    if failed_imports:
        print(f"\n⚠️  Missing modules: {', '.join(failed_imports)}")
        print("Install with: pip install -r requirements.txt")
        return False
    
    return True

def test_external_tools():
    """Test if external tools are available"""
    print("\n🔧 Testing external tools...")
    
    tools = {
        'nmap': 'Port scanning tool',
        'nuclei': 'Vulnerability scanner (optional)'
    }
    
    missing_tools = []
    
    for tool, description in tools.items():
        try:
            result = subprocess.run([tool, '--version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"✅ {tool} - {description}")
            else:
                print(f"❌ {tool} - {description} (Not working)")
                missing_tools.append(tool)
        except FileNotFoundError:
            print(f"❌ {tool} - {description} (Not found)")
            missing_tools.append(tool)
        except Exception as e:
            print(f"❌ {tool} - {description} (Error: {e})")
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"\n⚠️  Missing tools: {', '.join(missing_tools)}")
        print("Install with:")
        print("  - nmap: sudo apt install nmap")
        print("  - nuclei: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")
        return False
    
    return True

def test_network_connectivity():
    """Test basic network connectivity"""
    print("\n🌐 Testing network connectivity...")
    
    test_hosts = ['8.8.8.8', 'google.com']
    
    for host in test_hosts:
        try:
            socket.gethostbyname(host)
            print(f"✅ {host} - Reachable")
        except Exception as e:
            print(f"❌ {host} - Not reachable ({e})")
            return False
    
    return True

def test_basic_functionality():
    """Test basic blackmirror functionality"""
    print("\n🧪 Testing basic functionality...")
    
    try:
        # Test configuration loading
        from modules.config import Config
        config = Config()
        print("✅ Configuration loading - Working")
        
        # Test port scanner initialization
        from modules.port_scanner import PortScanner
        scanner = PortScanner(config)
        print("✅ Port scanner initialization - Working")
        
        # Test web recon initialization
        from modules.web_recon import WebRecon
        web_recon = WebRecon(config)
        print("✅ Web recon initialization - Working")
        
        # Test SSL analyzer initialization
        from modules.ssl_analyzer import SSLAnalyzer
        ssl_analyzer = SSLAnalyzer(config)
        print("✅ SSL analyzer initialization - Working")
        
        # Test vulnerability scanner initialization
        from modules.vuln_scanner import VulnScanner
        vuln_scanner = VulnScanner(config)
        print("✅ Vulnerability scanner initialization - Working")
        
        # Test passive recon initialization
        from modules.passive_recon import PassiveRecon
        passive_recon = PassiveRecon(config)
        print("✅ Passive recon initialization - Working")
        
        # Test report generator initialization
        from modules.report_generator import ReportGenerator
        report_gen = ReportGenerator(config)
        print("✅ Report generator initialization - Working")
        
        return True
        
    except Exception as e:
        print(f"❌ Basic functionality test failed: {e}")
        return False

def test_api_keys():
    """Test if API keys are configured"""
    print("\n🔑 Testing API configuration...")
    
    api_keys = {
        'SHODAN_API_KEY': 'Shodan API',
        'CENSYS_API_ID': 'Censys API ID',
        'CENSYS_API_SECRET': 'Censys API Secret',
        'VIRUSTOTAL_API_KEY': 'VirusTotal API'
    }
    
    configured_keys = []
    
    for key, description in api_keys.items():
        value = os.getenv(key)
        if value:
            print(f"✅ {description} - Configured")
            configured_keys.append(description)
        else:
            print(f"⚠️  {description} - Not configured")
    
    if configured_keys:
        print(f"\n✅ {len(configured_keys)} API keys configured")
    else:
        print("\n⚠️  No API keys configured (some features will be limited)")
        print("Set API keys for enhanced functionality:")
        print("  export SHODAN_API_KEY='your-key'")
        print("  export CENSYS_API_ID='your-id'")
        print("  export CENSYS_API_SECRET='your-secret'")
    
    return True

def test_file_permissions():
    """Test file permissions and accessibility"""
    print("\n📁 Testing file permissions...")
    
    files_to_check = [
        'blackmirror.py',
        'requirements.txt',
        'config.yaml',
        'modules/__init__.py',
        'modules/config.py',
        'modules/port_scanner.py',
        'modules/web_recon.py',
        'modules/ssl_analyzer.py',
        'modules/vuln_scanner.py',
        'modules/passive_recon.py',
        'modules/report_generator.py'
    ]
    
    missing_files = []
    
    for file_path in files_to_check:
        if os.path.exists(file_path):
            # Check if file is readable
            try:
                with open(file_path, 'r') as f:
                    f.read(1)
                print(f"✅ {file_path} - Readable")
            except Exception as e:
                print(f"❌ {file_path} - Not readable ({e})")
                missing_files.append(file_path)
        else:
            print(f"❌ {file_path} - Not found")
            missing_files.append(file_path)
    
    if missing_files:
        print(f"\n⚠️  Missing files: {', '.join(missing_files)}")
        return False
    
    return True

def test_demo_mode():
    """Test demo mode functionality"""
    print("\n🎭 Testing demo mode...")
    
    try:
        # Import and run demo
        import demo
        print("✅ Demo module - Working")
        return True
    except Exception as e:
        print(f"❌ Demo module failed: {e}")
        return False

def run_quick_scan_test():
    """Run a quick scan test on localhost"""
    print("\n🔍 Running quick scan test...")
    
    try:
        # Test with localhost (safe)
        test_target = "127.0.0.1"
        
        # Import main scanner
        from blackmirror import BlackMirrorScanner
        
        # Initialize scanner
        scanner = BlackMirrorScanner(test_target)
        
        # Run basic port scan
        results = scanner.scan_ports()
        
        if 'error' not in results:
            print("✅ Quick scan test - Successful")
            return True
        else:
            print(f"⚠️  Quick scan test - Limited ({results.get('error', 'Unknown error')})")
            return True  # Don't fail the test for this
            
    except Exception as e:
        print(f"❌ Quick scan test failed: {e}")
        return False

def main():
    """Run all tests"""
    print_banner()
    
    print("🧪 blackmirror Test Suite")
    print("=" * 50)
    
    tests = [
        ("Python Version", test_python_version),
        ("Python Imports", test_imports),
        ("External Tools", test_external_tools),
        ("Network Connectivity", test_network_connectivity),
        ("Basic Functionality", test_basic_functionality),
        ("API Configuration", test_api_keys),
        ("File Permissions", test_file_permissions),
        ("Demo Mode", test_demo_mode),
        ("Quick Scan Test", run_quick_scan_test)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                print(f"❌ {test_name} - FAILED")
        except Exception as e:
            print(f"❌ {test_name} - ERROR: {e}")
        print()
    
    print("=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! blackmirror is ready to use.")
        print("\nTry running:")
        print("  python blackmirror.py example.com")
        print("  python demo.py")
    elif passed >= total * 0.8:
        print("✅ Most tests passed! blackmirror should work with some limitations.")
        print("\nTry running:")
        print("  python blackmirror.py example.com")
    else:
        print("⚠️  Many tests failed. Please check the installation.")
        print("\nRun the installation script:")
        print("  python install.py")
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main()) 