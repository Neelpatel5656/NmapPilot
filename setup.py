import re
from setuptools import setup, find_packages

# Read version from __init__.py
with open("nmappilot/__init__.py") as f:
    version = re.search(r'__version__\s*=\s*"(.+?)"', f.read()).group(1)

# Read long description from README
with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="nmappilot",
    version=version,
    description="Automated Nmap Scanning & Vulnerability Analysis Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Neel Patel",
    author_email="",
    url="https://github.com/Neelpatel5656/NmapPilot",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "flask",
        "flask-socketio",
        "requests",
        "qrcode",
    ],
    package_data={
        "nmappilot": [
            "templates/*.html",
            "static/css/*.css",
            "static/js/*.js",
        ],
    },
    entry_points={
        "console_scripts": [
            "nmappilot=nmappilot.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
    ],
)
