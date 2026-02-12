from setuptools import setup, find_packages

setup(
    name="netsec-scanner",
    version="1.0.0",
    description="Network device security scanner with automated vulnerability assessment",
    author="Kassidy Clark",
    author_email="me@kasclark.com",
    url="https://github.com/kasclark/netsec-scanner",
    packages=find_packages(),
    include_package_data=True,
    package_data={"netsec_scanner": ["data/*.json"]},
    install_requires=[
        "python-nmap>=0.7.1",
        "paramiko>=3.0.0",
        "requests>=2.28.0",
        "click>=8.1.0",
        "rich>=13.0.0",
        "Jinja2>=3.1.0",
    ],
    entry_points={
        "console_scripts": [
            "netsec-scanner=netsec_scanner.cli:cli",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
    ],
)
