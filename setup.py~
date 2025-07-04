from setuptools import setup, find_packages

setup(
    name="zhesp2",                            # Your package name
    version="0.0.4",                          # Bump this for each upload
    author="ZeroDay",                         # Your name or alias
    description="Z-HESP2: Zero's Hash Encryption Secure Protocol (v2)",
    packages=find_packages(),
    python_requires=">=3.7",
    install_requires=[
        "argon2-cffi",
    ],
    entry_points={
        "console_scripts": [
            "zhesp2=zhesp.console:main",     # CLI command → zhesp.console.main()
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security :: Cryptography",
    ],
    include_package_data=True,
    zip_safe=False
)
