from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="red-team-toolkit",
    version="0.1.0",
    author="Red Team Development",
    description="A comprehensive penetration testing and vulnerability scanning automation framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/giotqz/red-team-toolkit",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.31.0",
        "pyyaml>=6.0",
        "python-dotenv>=1.0.0",
        "scapy>=2.5.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=4.9.0",
        "paramiko>=3.3.0",
        "cryptography>=41.0.0",
        "pycryptodome>=3.18.0",
        "jinja2>=3.1.0",
        "colorama>=0.4.6",
        "tqdm>=4.66.0",
        "tabulate>=0.9.0",
    ],
)
