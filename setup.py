#!/usr/bin/env python

from pathlib import Path

from setuptools import find_packages, setup

try:
    from pipenv.project import Project
    from pipenv.utils import convert_deps_to_pip

    pfile = Project().parsed_pipfile
    requirements = convert_deps_to_pip(pfile["packages"], r=False)
    test_requirements = convert_deps_to_pip(pfile["dev-packages"], r=False)
except ImportError:
    # get the requirements from the requirements.txt
    requirements_path = Path("requirements.txt")
    requirements = [
        line.strip()
        for line in requirements_path.read_text().splitlines()
        if line.strip() 
        and not line.startswith("#")
        and not line.startswith("-i")
        and not line.startswith("-f")
        and not line.startswith("--")
    ]
    # get the test requirements from the test_requirements.txt
    dev_requirements_path = Path("dev-requirements.txt")
    test_requirements = [
        line.strip()
        for line in dev_requirements_path.read_text().splitlines()
        if line.strip() 
        and not line.startswith("#")
        and not line.startswith("-i")
        and not line.startswith("-f")
        and not line.startswith("--")
    ]

readme = Path("README.rst").read_text()
history = Path("HISTORY.rst").read_text().replace(".. :changelog:", "")
version = Path(".VERSION").read_text()


setup(
    name="""awsenergylabelercli""",
    version=version,
    description="""A cli to label accounts and landing zones with energy labels based on Security Hub finding.""",
    long_description=readme + "\n\n" + history,
    author="""Theodoor Scholte""",
    author_email="""tscholte@schubergphilis.com""",
    url="""https://github.com/schubergphilis/awsenergylabelercli.git""",
    packages=find_packages(where=".", exclude=("tests", "hooks", "_CI*")),
    package_dir={"""awsenergylabelercli""": """awsenergylabelercli"""},
    include_package_data=True,
    install_requires=requirements,
    license="MIT",
    zip_safe=False,
    keywords="""awsenergylabelercli energy labeler aws security hub""",
    entry_points={
        "console_scripts": [
            # enable this to automatically generate a script in /usr/local/bin called myscript that points to your
            #  awsenergylabelercli.awsenergylabelercli:main method
            "aws-energy-labeler = aws_energy_labeler_cli:main",
        ],
    },
    scripts=["aws_energy_labeler_cli.py"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3.14",
    ],
)
