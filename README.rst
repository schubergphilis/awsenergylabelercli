===================
awsenergylabelercli
===================

[![CI/CD Pipeline](https://github.com/Joeri-Abbo/awsenergylabelercli/actions/workflows/main.yml/badge.svg)](https://github.com/Joeri-Abbo/awsenergylabelercli/actions/workflows/main.yml)

A CLI tool to label AWS accounts and landing zones with energy labels based on Security Hub findings.

|PyPI version| |Python versions| |License| |Build Status|

.. |PyPI version| image:: https://img.shields.io/pypi/v/awsenergylabelercli.svg
   :target: https://pypi.org/project/awsenergylabelercli/

.. |Python versions| image:: https://img.shields.io/pypi/pyversions/awsenergylabelercli.svg
   :target: https://pypi.org/project/awsenergylabelercli/

.. |License| image:: https://img.shields.io/github/license/schubergphilis/awsenergylabelercli.svg
   :target: https://github.com/schubergphilis/awsenergylabelercli/blob/main/LICENSE

.. |Build Status| image:: https://github.com/schubergphilis/awsenergylabelercli/workflows/CI%2FCD%20Pipeline/badge.svg
   :target: https://github.com/schubergphilis/awsenergylabelercli/actions

* Documentation: https://aws-energy-labeler-cli.readthedocs.io/en/latest/

Features
========

* Generate energy efficiency labels for AWS accounts based on Security Hub findings
* Support for multiple output formats (JSON, reports)
* Comprehensive security analysis and recommendations
* CLI interface for easy automation and integration

Installation
============

Install the latest version from PyPI:

.. code-block:: bash

    pip install awsenergylabelercli

Or install from source:

.. code-block:: bash

    git clone https://github.com/schubergphilis/awsenergylabelercli.git
    cd awsenergylabelercli
    pip install .

Usage
=====

Basic usage:

.. code-block:: bash

    aws-energy-labeler-cli --help

For detailed usage instructions, see the `documentation <https://aws-energy-labeler-cli.readthedocs.io/en/latest/>`_.

Development
===========

This project uses modern Python development practices with automated CI/CD.

Setting up the development environment:

.. code-block:: bash

    git clone https://github.com/schubergphilis/awsenergylabelercli.git
    cd awsenergylabelercli
    python -m venv .venv
    source .venv/bin/activate  # On Windows: .venv\Scripts\activate
    pip install -r requirements.txt
    pip install -r dev-requirements.txt


Development Workflow
===================

This project uses GitHub Actions for automated CI/CD with the following pipeline:

**Automated CI/CD Pipeline:**

* **Linting**: Automated code quality checks with pylint and ruff
* **Testing**: Comprehensive test suite with coverage reporting
* **Building**: Automated package building with setuptools
* **Publishing**: Automatic PyPI publishing on git tags

**Local Development Commands:**

.. code-block:: bash

    # Run linting
    ruff check .
    pylint awsenergylabelercli/ aws_energy_labeler_cli.py
    
    # Run tests with coverage
    python -m pytest tests/ --cov=awsenergylabelercli --cov-report=html --cov-report=term-missing
    
    # Build package
    python -m build
    
    # Check package
    twine check dist/*

**Release Process:**

1. Make your changes and ensure all tests pass
2. Update version number and changelog as needed
3. Create and push a git tag:

.. code-block:: bash

    git tag v6.0.1
    git push origin v6.0.1

4. The GitHub Actions pipeline will automatically:
   - Run all tests and linting
   - Build the package
   - Publish to PyPI (if all checks pass)

**Legacy Scripts:**

The project includes legacy scripts under ``scripts/`` directory for manual operations:

* ``scripts/build.sh`` - Manual build process
* ``scripts/lint.sh`` - Manual linting
* ``scripts/test.sh`` - Manual testing
* ``scripts/upload.sh`` - Manual upload to PyPI

However, the recommended approach is to use the automated GitHub Actions pipeline.

Requirements and Dependencies
============================

This project supports both traditional requirements.txt and modern pipenv/pyproject.toml configurations:

* **Runtime dependencies**: Listed in ``requirements.txt``
* **Development dependencies**: Listed in ``dev-requirements.txt``
* **Build configuration**: Defined in ``pyproject.toml``
* **Legacy pipenv**: Supported via ``Pipfile`` and ``Pipfile.lock``

The build system automatically handles dependency resolution and is compatible with the broader Python ecosystem.


Contributing
============

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create a feature branch (``git checkout -b feature/amazing-feature``)
3. Make your changes
4. Add tests for your changes
5. Ensure all tests pass and linting is clean
6. Commit your changes (``git commit -m 'Add amazing feature'``)
7. Push to the branch (``git push origin feature/amazing-feature``)
8. Open a Pull Request

The automated CI/CD pipeline will validate your changes before they can be merged.

License
=======

This project is licensed under the MIT License - see the LICENSE file for details.

Changelog
=========

See `HISTORY.rst <HISTORY.rst>`_ for a detailed changelog.

Support
=======

If you encounter any issues or have questions, please:

1. Check the `documentation <https://aws-energy-labeler-cli.readthedocs.io/en/latest/>`_
2. Search existing `GitHub Issues <https://github.com/schubergphilis/awsenergylabelercli/issues>`_
3. Create a new issue if needed

Links
=====

* Documentation: https://aws-energy-labeler-cli.readthedocs.io/en/latest/
* PyPI: https://pypi.org/project/awsenergylabelercli/
* Source Code: https://github.com/schubergphilis/awsenergylabelercli
* Issue Tracker: https://github.com/schubergphilis/awsenergylabelercli/issues
