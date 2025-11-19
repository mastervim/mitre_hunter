from setuptools import setup, find_packages

setup(
    name="mitre_hunter",
    version="1.0.0",
    description="A threat hunting tool for querying MITRE ATT&CK TTPs by Data Source",
    author="MitreHunter Team",
    packages=find_packages(),
    install_requires=[
        "requests",
        "pandas",
        "rich",
        "streamlit",
        "stix2",
    ],
    entry_points={
        "console_scripts": [
            "mitre-hunter=src.cli:main",
        ],
    },
    python_requires=">=3.8",
)
