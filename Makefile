.PHONY: help install test clean build publish

help:  ## 显示帮助信息
	@echo '可用命令:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install:  ## 安装依赖
	pip install -r requirements.txt
	pip install -e .

install-dev:  ## 安装开发依赖
	pip install -r requirements-dev.txt
	pre-commit install

test:  ## 运行测试
	pytest tests/ -v

test-cov:  ## 运行测试并生成覆盖率报告
	pytest --cov=security_guard tests/

lint:  ## 代码检查
	flake8 security_guard/
	black --check security_guard/
	mypy security_guard/

format:  ## 格式化代码
	black security_guard/
	isort security_guard/

clean:  ## 清理临时文件
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf build/ dist/ .pytest_cache/ .coverage

build:  ## 构建发布包
	python setup.py sdist bdist_wheel

publish:  ## 发布到PyPI
	twine upload dist/*

scan:  ## 扫描所有skills
	python -m security_guard scan --all

quick-check:  ## 快速安全检查
	python -m security_guard quick-check

report:  ## 生成安全报告
	python -m security_guard report --output security_report.txt

monitor:  ## 启动实时监控
	python -m security_guard monitor

stats:  ## 查看统计信息
	python -m security_guard stats

demo:  ## 运行演示
	python examples/basic_usage.py
