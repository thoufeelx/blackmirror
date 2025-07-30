#!/usr/bin/env python3
"""
Setup script for blackmirror
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="blackmirror",
    version="1.0.0",
    author="blackmirror",
    author_email="",
    description="A powerful, modular reconnaissance tool for ethical hacking",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/blackmirror",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "blackmirror=blackmirror:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
) 