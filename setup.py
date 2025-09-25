"""
QuantumSentinel-Nexus Setup Configuration
The Ultimate AI Cybersecurity Command Platform
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the contents of README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name="quantumsentinel-nexus",
    version="2.0.0-QUANTUM",
    author="QuantumSentinel-Nexus Team",
    author_email="team@quantumsentinel-nexus.com",
    description="⚡ The Ultimate AI Cybersecurity Command Platform with Quantum-Inspired Intelligence",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Rudra2018/QuantumSentinel-Nexus",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
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
        "pandas>=1.5.0",
        "numpy>=1.21.0",
        "scikit-learn>=1.1.0",
        "matplotlib>=3.5.0",
        "seaborn>=0.11.0",
        "colorama>=0.4.5",
        "tqdm>=4.64.0",
        "click>=8.1.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
        ],
        "docs": [
            "mkdocs>=1.4.0",
            "mkdocs-material>=8.5.0",
        ],
        "ml": [
            "tensorflow>=2.8.0",
            "torch>=1.12.0",
            "xgboost>=1.6.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "aegislearner=aegislearner:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)