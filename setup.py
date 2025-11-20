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
