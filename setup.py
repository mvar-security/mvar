"""
MVAR — MIRRA Verified Agent Runtime
Setup script for pip installation
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

setup(
    name="mvar",
    version="1.0.0",
    author="Shawn Cohen",
    author_email="security@mvar.io",
    description="MVAR: Information Flow Control for LLM Agent Runtimes — Deterministic prompt injection defense via dual-lattice IFC with cryptographic provenance",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mvar-security/mvar",
    license="Apache 2.0",
    license_files=("LICENSE.md",),
    packages=find_packages(where=".", exclude=["mvar-core", "mvar-core.*"]) + ["mvar_core"],
    package_dir={"mvar_core": "mvar-core"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.10",
    install_requires=[
        "numpy>=1.24.0,<3.0.0",
        "cryptography>=41.0.0,<47.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0,<8.0.0",
            "pytest-cov>=4.1.0,<5.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "mvar-demo=demo.openclaw_cve_defense:main",
            "mvar=demo.info:main",
            "mvar-doctor=demo.info:doctor_main",
            # NEW: Decision ledger CLI commands
            "mvar-report=mvar_core.cli_ledger:main_report",
            "mvar-explain=mvar_core.cli_ledger:main_explain",
            "mvar-allow=mvar_core.cli_ledger:main_allow",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
