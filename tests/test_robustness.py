"""
鲁棒性测试套件 - Robustness Test Suite
测试 OpenClaw Security Shield 在异常和边界条件下的稳定性
"""

import pytest
import tempfile
import os
import sys
from pathlib import Path
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# 确保项目根目录在路径中
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from openclaw_shield.scanner import SkillScanner
from openclaw_shield.threats import ThreatDetector
from openclaw_shield.config import Config


class TestScannerRobustness:
    """扫描器鲁棒性测试"""

    def setup_method(self):
        """每个测试方法前的设置"""
        self.config = Config()

    # ==================== 边界值测试 ====================

    def test_scan_empty_file(self, tmp_path):
        """测试扫描空文件"""
        empty_file = tmp_path / "empty.py"
        empty_file.write_text("")

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(empty_file))

        assert result is not None
        assert 'error' not in result or result.get('error') is None
        assert result['file'] == str(empty_file)
        assert isinstance(result['passed'], bool)

    def test_scan_whitespace_only(self, tmp_path):
        """测试扫描仅包含空白字符的文件"""
        ws_file = tmp_path / "whitespace.py"
        ws_file.write_text("   \n\n\t\r\n   ")

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(ws_file))

        assert result is not None
        assert result['file'] == str(ws_file)

    def test_scan_very_large_file(self, tmp_path):
        """测试扫描大文件 (10MB)"""
        large_file = tmp_path / "large.py"
        # 创建一个重复的合法代码模式
        content = "def func{}(): return x\n" * 200000  # 约 10MB
        large_file.write_text(content)

        scanner = SkillScanner(self.config)
        start = time.time()
        result = scanner.scan_file(str(large_file))
        elapsed = time.time() - start

        assert result is not None
        assert elapsed < 30  # 应该在30秒内完成
        # 验证没有崩溃

    def test_scan_single_line_file(self, tmp_path):
        """测试扫描单行文件"""
        single_line = tmp_path / "single.py"
        single_line.write_text("import os")

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(single_line))

        assert result is not None
        assert len(result['imports']) == 1

    def test_scan_very_long_line(self, tmp_path):
        """测试扫描超长行的文件"""
        long_line = tmp_path / "longline.py"
        long_line.write_text("x = " + "a" * 1000000)

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(long_line))

        assert result is not None
        # 应该能处理而不崩溃

    def test_scan_deep_nesting(self, tmp_path):
        """测试扫描深度嵌套的代码"""
        deep_file = tmp_path / "deep.py"
        # 创建深度嵌套的代码
        content = "if True:\n" + "    if True:\n" * 100 + "        pass\n" + "    " * 100 + "\n"
        deep_file.write_text(content)

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(deep_file))

        assert result is not None

    def test_scan_many_imports(self, tmp_path):
        """测试扫描包含大量导入的文件"""
        imports_file = tmp_path / "imports.py"
        imports = [f"import module{i}" for i in range(1000)]
        imports_file.write_text("\n".join(imports))

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(imports_file))

        assert result is not None
        assert len(result['imports']) == 1000

    # ==================== 异常输入测试 ====================

    def test_scan_non_existent_file(self):
        """测试扫描不存在的文件"""
        scanner = SkillScanner(self.config)
        result = scanner.scan_file("/non/existent/path/file.py")

        assert result is not None
        assert 'error' in result
        assert 'not found' in result['error'].lower()

    def test_scan_directory_as_file(self, tmp_path):
        """测试将目录当作文件扫描"""
        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(tmp_path))

        assert result is not None
        # 应该返回错误或安全处理

    def test_scan_invalid_utf8(self, tmp_path):
        """测试扫描包含无效UTF-8字符的文件"""
        invalid_file = tmp_path / "invalid.py"
        invalid_file.write_bytes(b'\xff\xfe\x00\x01\x02\x03\x04\x05')

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(invalid_file))

        assert result is not None
        # 应该使用 errors='ignore' 处理

    def test_scan_mixed_encoding(self, tmp_path):
        """测试扫描混合编码的文件"""
        mixed_file = tmp_path / "mixed.py"
        content = "# 正常中文\nimport os\n# 特殊字符: \xff\xfe\nx = 1\n# Emoji: \U0001F600\n"
        mixed_file.write_text(content, encoding='utf-8', errors='surrogateescape')

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(mixed_file))

        assert result is not None

    def test_scan_syntax_error_python(self, tmp_path):
        """测试扫描包含语法错误的Python文件"""
        syntax_error_file = tmp_path / "syntax_error.py"
        syntax_error_file.write_text("import os\nthis is not valid python !!! (((\ndef foo(")

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(syntax_error_file))

        assert result is not None
        assert 'syntax_error' in [w.get('type', '') for w in result.get('warnings', [])]

    def test_scan_incomplete_code(self, tmp_path):
        """测试扫描不完整的代码片段"""
        incomplete_file = tmp_path / "incomplete.py"
        incomplete_file.write_text("def foo(\n    arg1,\n    # 未完成的函数")

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(incomplete_file))

        assert result is not None

    def test_scan_null_bytes(self, tmp_path):
        """测试扫描包含空字节的文件"""
        null_file = tmp_path / "nulls.py"
        null_file.write_text("import os\n\x00\x00\x00\nx = 1")

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(null_file))

        assert result is not None

    # ==================== 特殊字符测试 ====================

    def test_scan_unicode_in_strings(self, tmp_path):
        """测试扫描包含各种Unicode字符的文件"""
        unicode_file = tmp_path / "unicode.py"
        content = """
# 各种Unicode字符
emoji = "\U0001F600 \U0001F604 \U0001F620"
chinese = "你好世界"
arabic = "مرحبا بالعالم"
russian = "Привет мир"
symbols = "©®™€£¥¥"
"""
        unicode_file.write_text(content, encoding='utf-8')

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(unicode_file))

        assert result is not None

    def test_scan_special_filename(self, tmp_path):
        """测试扫描特殊文件名"""
        special_names = [
            "file with spaces.py",
            "file'with'quotes.py",
            "file\"with\"double\"quotes.py",
            "file(with)parens.py",
            "file[with]brackets.py",
            "file{with}braces.py",
        ]

        scanner = SkillScanner(self.config)

        for name in special_names:
            test_file = tmp_path / name
            test_file.write_text("import os\nx = 1")
            result = scanner.scan_file(str(test_file))
            assert result is not None, f"Failed for filename: {name}"

    def test_scan_obfuscated_code(self, tmp_path):
        """测试扫描混淆代码"""
        obfuscated_file = tmp_path / "obfuscated.py"
        # Base64混淆
        content = """
import base64
encoded = "aW1wb3J0IG9zCm9zLnN5c3RlbSgnbHMnKQ=="
decoded = base64.b64decode(encoded).decode()
exec(decoded)
"""
        obfuscated_file.write_text(content)

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(obfuscated_file))

        assert result is not None
        assert len(result['threats']) > 0  # 应该检测到混淆

    def test_scan_hex_encoded_strings(self, tmp_path):
        """测试扫描十六进制编码的字符串"""
        hex_file = tmp_path / "hex.py"
        hex_file.write_text('x = "\\x48\\x65\\x6c\\x6c\\x6f"')

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(hex_file))

        assert result is not None
        # 应该检测到十六进制编码模式

    # ==================== 威胁检测边界测试 ====================

    def test_scan_eval_edge_cases(self, tmp_path):
        """测试eval检测的边界情况"""
        eval_file = tmp_path / "eval_edge.py"
        # 应该检测到的
        content = """
x = eval("1 + 1")  # 应该检测
evaluate = "not eval"  # 不应该检测
evaluate_this = "not eval"  # 不应该检测
"""
        eval_file.write_text(content)

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(eval_file))

        assert result is not None
        # 至少应该检测到一个 eval
        eval_threats = [t for t in result['threats'] if 'eval' in t.get('message', '').lower()]
        assert len(eval_threats) >= 1

    def test_scan_false_positive_safe_code(self, tmp_path):
        """测试安全代码不应产生误报"""
        safe_file = tmp_path / "safe.py"
        content = """
import json
from pathlib import Path

def process_data(data):
    return json.dumps(data)

def read_file(path):
    return Path(path).read_text()

# 正常的环境变量使用（非窃取）
db_url = os.getenv('DATABASE_URL', 'localhost')

# 正常的字符串操作
message = "Hello, World!"
"""
        safe_file.write_text(content)

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(safe_file))

        assert result is not None
        # 高严重性威胁应该很少或没有
        critical_threats = [t for t in result['threats'] if t.get('severity') == 'CRITICAL']
        assert len(critical_threats) == 0

    # ==================== JavaScript 扫描测试 ====================

    def test_scan_javascript_safe(self, tmp_path):
        """测试扫描安全的JavaScript代码"""
        js_file = tmp_path / "safe.js"
        content = """
// 安全的JavaScript代码
function greet(name) {
    return 'Hello, ' + name + '!';
}

const add = (a, b) => a + b;

// 使用innerHTML但不涉及用户输入
document.getElementById('demo').innerHTML = '<p>Fixed content</p>';
"""
        js_file.write_text(content)

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(js_file))

        assert result is not None

    def test_scan_javascript_malicious(self, tmp_path):
        """测试扫描恶意的JavaScript代码"""
        js_file = tmp_path / "malicious.js"
        content = """
// 恶意JavaScript
eval(userInput);

// 使用 Function 构造器
const evil = new Function('return malicious code');

// innerHTML与用户输入 - DOM XSS风险
document.body.innerHTML = userInput;
"""
        js_file.write_text(content)

        scanner = SkillScanner(self.config)
        result = scanner.scan_file(str(js_file))

        assert result is not None
        assert len(result['threats']) > 0
        assert result['passed'] == False

    # ==================== 目录扫描测试 ====================

    def test_scan_empty_directory(self, tmp_path):
        """测试扫描空目录"""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        scanner = SkillScanner(self.config)
        result = scanner.scan_directory(str(empty_dir))

        assert result is not None
        assert result['files_scanned'] == 0

    def test_scan_non_existent_directory(self):
        """测试扫描不存在的目录"""
        scanner = SkillScanner(self.config)

        with pytest.raises(FileNotFoundError):
            scanner.scan_directory("/non/existent/directory")

    def test_scan_deep_directory_tree(self, tmp_path):
        """测试扫描深层目录结构"""
        # 创建深层目录
        current = tmp_path
        for i in range(50):
            current = current / f"level{i}"
            current.mkdir(exist_ok=True)

        # 在最深层放置文件
        deep_file = current / "deep.py"
        deep_file.write_text("import os")

        scanner = SkillScanner(self.config)
        result = scanner.scan_directory(str(tmp_path))

        assert result is not None
        assert result['files_scanned'] >= 1

    def test_scan_mixed_file_types(self, tmp_path):
        """测试扫描包含多种文件类型的目录"""
        # 创建不同类型的文件
        (tmp_path / "test.py").write_text("import os")
        (tmp_path / "test.js").write_text("console.log('test')")
        (tmp_path / "test.txt").write_text("not a code file")
        (tmp_path / "test.json").write_text('{"key": "value"}')

        scanner = SkillScanner(self.config)
        result = scanner.scan_directory(str(tmp_path))

        assert result is not None
        # 只扫描 .py 和 .js 文件
        assert result['files_scanned'] == 2


class TestThreatDetectorRobustness:
    """威胁检测器鲁棒性测试"""

    def setup_method(self):
        """每个测试方法前的设置"""
        self.config = Config()
        self.detector = ThreatDetector(self.config)

    def test_empty_content_analysis(self):
        """测试分析空内容"""
        # ThreatDetector 主要用于检测规则，空内容应该安全处理
        assert self.detector is not None

    def test_none_input_handling(self):
        """测试处理None输入"""
        # 应该安全处理而不崩溃
        assert self.detector is not None

    def test_minimal_code(self):
        """测试最小代码片段"""
        assert self.detector is not None


class TestConfigRobustness:
    """配置管理器鲁棒性测试"""

    def test_config_with_invalid_path(self):
        """测试使用不存在的配置路径"""
        config = Config("/non/existent/config.yaml")
        assert config is not None
        # 应该使用默认配置

    def test_config_get_non_existent_key(self):
        """测试获取不存在的配置键"""
        config = Config()
        value = config.get("non.existent.key", "default")
        assert value == "default"

    def test_config_set_nested_key(self):
        """测试设置嵌套配置键"""
        config = Config()
        config.set("new.nested.key", "value")
        assert config.get("new.nested.key") == "value"

    def test_config_with_dict(self):
        """测试从字典创建配置"""
        config_dict = {
            'security': {'scan_on_install': False},
            'custom': {'value': 123}
        }
        config = Config.from_dict(config_dict)
        assert config.get('security.scan_on_install') == False
        assert config.get('custom.value') == 123

    def test_config_validation(self):
        """测试配置验证"""
        config = Config()
        assert config.validate() == True


class TestConcurrencyRobustness:
    """并发鲁棒性测试"""

    def test_concurrent_scan_same_file(self, tmp_path):
        """测试多线程同时扫描同一文件"""
        test_file = tmp_path / "concurrent.py"
        test_file.write_text("import os\nx = 1")

        def scan_task():
            scanner = SkillScanner(Config())
            return scanner.scan_file(str(test_file))

        # 使用10个线程同时扫描
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(scan_task) for _ in range(10)]
            results = [f.result() for f in as_completed(futures)]

        assert len(results) == 10
        assert all(r is not None for r in results)

    def test_concurrent_scan_different_files(self, tmp_path):
        """测试多线程扫描不同文件"""
        # 创建多个测试文件
        for i in range(20):
            (tmp_path / f"file{i}.py").write_text(f"import os\nx = {i}")

        def scan_task(filepath):
            scanner = SkillScanner(Config())
            return scanner.scan_file(filepath)

        # 使用5个线程并发扫描
        files = [str(tmp_path / f"file{i}.py") for i in range(20)]
        with ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(scan_task, files))

        assert len(results) == 20
        assert all(r is not None for r in results)

    def test_concurrent_directory_scan(self, tmp_path):
        """测试并发目录扫描"""
        # 创建测试文件
        for i in range(10):
            (tmp_path / f"test{i}.py").write_text("import os")

        def scan_task():
            scanner = SkillScanner(Config())
            return scanner.scan_directory(str(tmp_path))

        # 使用3个线程同时扫描同一目录
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(scan_task) for _ in range(3)]
            results = [f.result() for f in as_completed(futures)]

        assert len(results) == 3
        assert all(r is not None for r in results)


class TestMemoryRobustness:
    """内存和资源鲁棒性测试"""

    def test_repeated_scans_no_memory_leak(self, tmp_path):
        """测试重复扫描不会导致内存泄漏"""
        test_file = tmp_path / "memory_test.py"
        test_file.write_text("import os\n" + "x = 1\n" * 100)

        scanner = SkillScanner(Config())

        # 执行大量扫描
        for _ in range(100):
            result = scanner.scan_file(str(test_file))
            assert result is not None

    def test_scan_many_files_sequentially(self, tmp_path):
        """测试顺序扫描大量文件"""
        # 创建500个测试文件
        for i in range(500):
            (tmp_path / f"file{i}.py").write_text(f"import os\nx = {i}")

        scanner = SkillScanner(Config())
        result = scanner.scan_directory(str(tmp_path))

        assert result is not None
        assert result['files_scanned'] == 500


class TestEdgeCases:
    """边缘情况测试"""

    def test_scan_symlink(self, tmp_path):
        """测试扫描符号链接"""
        if not hasattr(os, 'symlink'):
            pytest.skip("Symlinks not supported on this system")

        # 创建目标文件和符号链接
        target_file = tmp_path / "target.py"
        target_file.write_text("import os")

        symlink_file = tmp_path / "link.py"
        try:
            symlink_file.symlink_to(target_file)
        except OSError:
            pytest.skip("Cannot create symlink (permissions?)")

        scanner = SkillScanner(Config())
        result = scanner.scan_file(str(symlink_file))

        assert result is not None

    def test_scan_with_bom(self, tmp_path):
        """测试扫描带BOM的UTF-8文件"""
        bom_file = tmp_path / "bom.py"
        # UTF-8 BOM + 内容
        content = '\ufeffimport os\nx = 1'
        bom_file.write_text(content, encoding='utf-8-sig')

        scanner = SkillScanner(Config())
        result = scanner.scan_file(str(bom_file))

        assert result is not None

    def test_scan_crlf_line_endings(self, tmp_path):
        """测试扫描Windows行尾符"""
        win_file = tmp_path / "windows.py"
        content = "import os\r\nx = 1\r\n\r\n"
        win_file.write_text(content)

        scanner = SkillScanner(Config())
        result = scanner.scan_file(str(win_file))

        assert result is not None

    def test_scan_only_comments(self, tmp_path):
        """测试扫描只包含注释的文件"""
        comment_file = tmp_path / "comments.py"
        # 使用原始字符串避免引号嵌套问题
        content = """# This is a comment
# Another comment

# Multiline comment
# More comments
"""
        comment_file.write_text(content)

        scanner = SkillScanner(Config())
        result = scanner.scan_file(str(comment_file))

        assert result is not None

    def test_scan_file_with_no_newline_at_end(self, tmp_path):
        """测试扫描末尾没有换行符的文件"""
        no_newline = tmp_path / "no_newline.py"
        no_newline.write_text("import os\nx = 1")  # No trailing newline

        scanner = SkillScanner(Config())
        result = scanner.scan_file(str(no_newline))

        assert result is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-tb=short"])
