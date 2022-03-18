#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
try:
    from pipenv.project import Project
    from pipenv.utils import convert_deps_to_pip

    pfile = Project().parsed_pipfile
    requirements = convert_deps_to_pip(pfile['packages'], r=False)
    test_requirements = convert_deps_to_pip(pfile['dev-packages'], r=False)
except ImportError:
    # get the requirements from the requirements.txt
    requirements = [line.strip()
                    for line in open('requirements.txt').readlines()
                    if line.strip() and not line.startswith('#')]
    # get the test requirements from the test_requirements.txt
    test_requirements = [line.strip()
                         for line in
                         open('dev-requirements.txt').readlines()
                         if line.strip() and not line.startswith('#')]

readme = open('README.rst').read()
history = open('HISTORY.rst').read().replace('.. :changelog:', '')
version = open('.VERSION').read()


setup(
    name='''awsenergylabelercli''',
    version=version,
    description='''A cli to label accounts and landing zones with energy labels based on Security Hub finding.''',
    long_description=readme + '\n\n' + history,
    author='''Theodoor Scholte''',
    author_email='''tscholte@schubergphilis.com''',
    url='''https://github.com/schubergphilis/awsenergylabelercli.git''',
    packages=find_packages(where='.', exclude=('tests', 'hooks', '_CI*')),
    package_dir={'''awsenergylabelercli''':
                 '''awsenergylabelercli'''},
    include_package_data=True,
    install_requires=requirements,
    license='MIT',
    zip_safe=False,
    keywords='''awsenergylabelercli energy labeler aws security hub''',
    entry_points={
        'console_scripts': [
            # enable this to automatically generate a script in /usr/local/bin called myscript that points to your
            #  awsenergylabelercli.awsenergylabelercli:main method
            'aws-energy-labeler = aws_energy_labeler_cli:main'
        ]},
    scripts=['aws_energy_labeler_cli.py'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.7',
        ],
    test_suite='tests',
    tests_require=test_requirements
)
