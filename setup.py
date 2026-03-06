#!/usr/bin/env python3

from setuptools import setup, find_packages

with open("SKILL.md", "r") as fh:
    long_description = fh.read()

setup(
    name="agent-guard",
    version="1.0.0", 
    author="Zak Cole",
    author_email="zak@numbergroup.xyz",
    description="Real-time prompt injection detection and sanitization for AI agents",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/zscole/ai-poc-daily/tree/main/2026-03-06",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.7",
    install_requires=[
        # No required dependencies - uses Python stdlib only
    ],
    extras_require={
        "mcp": ["mcp>=0.1.0"],
        "dev": ["pytest>=6.0.0", "black>=22.0.0"]
    },
    entry_points={
        "console_scripts": [
            "agent-guard=openclaw_integration:main",
        ],
    },
    py_modules=[
        "agent_guard",
        "mcp_server", 
        "openclaw_integration"
    ]
)