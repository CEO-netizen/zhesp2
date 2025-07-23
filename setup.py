from setuptools import setup, find_packages

setup(
    name="zhesp2",
    version="2.4.6",
    author="Zero",
    description="Z-HESP2 — Zero’s Hash Encryption Secure Protocol",
    long_description=open("README.md", "r", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.7",
    install_requires=[
        "pycryptodome>=3.19.0",
        "argon2-cffi>=21.3.0",
    ],
    entry_points={
        "console_scripts": [
            "zhesp2=zhesp2.__main__:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)"
    ],
)
