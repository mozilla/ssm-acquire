#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = ['Click>=6.0', 'pyyaml', 'boto3', 'everett[ini]', 'botocore', 'Jinja2>=2.10', 'docker', 'prompt-toolkit']

setup_requirements = ['pytest-runner']

test_requirements = ['pytest', 'pytest-watch', 'pytest-cov', 'moto']

setup(
    author="Andrew J Krug",
    author_email='andrewkrug@gmail.com',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
        'Natural Language :: English',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    description="A python module for orchestrating content acquisitions and light analysis via amazon ssm.",
    entry_points={
        'console_scripts': [
            'ssm_acquire=ssm_acquire.cli:main',
        ],
    },
    install_requires=requirements,
    license="MIT license",
    long_description=readme + '\n\n' + history,
    include_package_data=True,
    keywords='ssm_acquire',
    name='ssm_acquire',
    packages=find_packages(include=['ssm_acquire'], exclude=['*.aff4', 'tests/*/*.zip']),
    setup_requires=setup_requirements,
    test_suite='tests',
    tests_require=test_requirements,
    url='https://github.com/andrewkrug/ssm_acquire',
    version='0.1.0.5',
    zip_safe=False,
)
