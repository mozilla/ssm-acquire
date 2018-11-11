===========
ssm-acquire
===========


.. image:: https://img.shields.io/pypi/v/ssm_acquire.svg
        :target: https://pypi.python.org/pypi/ssm_acquire

.. image:: https://img.shields.io/travis/andrewkrug/ssm_acquire.svg
        :target: https://travis-ci.org/andrewkrug/ssm_acquire

.. image:: https://readthedocs.org/projects/ssm-acquire/badge/?version=latest
        :target: https://ssm-acquire.readthedocs.io/en/latest/?badge=latest
        :alt: Documentation Status

.. image:: https://pyup.io/repos/github/andrewkrug/ssm_acquire/shield.svg
     :target: https://pyup.io/repos/github/andrewkrug/ssm_acquire/
     :alt: Updates



A python module for orchestrating content acquisitions and analysis via amazon ssm.


* Free software: MPL 2.0 License
* Documentation: https://ssm-acquire.readthedocs.io.


Features
--------

* Acquire memory from a linux instance to an S3 bucket using SSM.
* Interrogate an instance for top-10 IOCs using OSQuery and save the jsonified output.
* Analyze a memory sample on a machine using docker.
* Create a rekall profile using an instance as a build target running the Amazon SSM Agent.

Credits
-------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
