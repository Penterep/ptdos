import sys
from setuptools import setup, find_packages
from ptdos.version import SCRIPTNAME, __version__

CURRENT_PYTHON = sys.version_info[:2]
REQUIRED_PYTHON = (3, 10)

if CURRENT_PYTHON < REQUIRED_PYTHON:
    print(f"Unsupported Python version! This version of ptdos requires at least Python {REQUIRED_PYTHON} but you are trying to install it on Python {CURRENT_PYTHON}. To resolve this, consider upgrading to a supported Python version.")
    sys.exit(1)

with open("README.md", "r") as file:
    long_description = file.read()

setup(
    name=SCRIPTNAME,
    description="Application ptdos is used for creation of DoS attacks. It is part of complex system Penterep Tools.",
    version=__version__,
    url="https://www.penterep.com/",
    author="Penterep",
    author_email="xkamen19@vutbr.cz",
    license="GPLv3",
    packages=find_packages(),
    classifiers=[
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3.10",
        "Environment :: Console",
        "Development Status :: 5 - Production/Stable",
        "Natural Language :: English",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS :: MacOS X",
        "Topic :: Security",
        "Topic :: Utilities"
    ],
    python_requires='>=3.10.0',
    install_requires=[
        "ptlibs>=0.0.6",
        "requests>=2.27.1",
        "validators>=0.18.2",
        "impacket>=0.9.24"
    ],
    entry_points={
        'console_scripts': [
            'ptdos = ptdos.ptdos:main'
        ]
    },
    include_package_data=True,
    long_description=long_description,
    long_description_content_type="text/markdown",
    project_urls={
            "Source": "https://github.com/FilipKam/ptdos",
    },
)
