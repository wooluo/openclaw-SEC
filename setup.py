"""
OpenClaw Security Guard - Setup
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="openclaw-security-guard",
    version="1.0.0",
    author="OpenClaw Community",
    author_email="security@openclaw.ai",
    description="Enterprise-grade security protection suite for OpenClaw AI assistant",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/openclaw-security-guard",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "colorama>=0.4.6",
        "pyyaml>=6.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "black>=22.0",
            "flake8>=4.0",
            "mypy>=0.950",
        ],
    },
    entry_points={
        "console_scripts": [
            "security-guard=security_guard.cli:main",
        ],
    },
)
