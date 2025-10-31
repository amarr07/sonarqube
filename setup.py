from setuptools import setup, find_packages

setup(
    name="mcphub",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "requests>=2.31.0",
        "click>=8.1.0",
        "boto3>=1.28.0",
        "urllib3>=2.0.0",
        "certifi>=2023.7.22",
    ],
    entry_points={
        "console_scripts": [
            "mcphub=mcphub.cli:main",
        ],
    },
    python_requires=">=3.8",
    author="Your Name",
    author_email="your.email@example.com",
    description="CLI tool for SonarQube analysis and MCP server registry management",
    url="https://github.com/yourusername/mcphub",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
