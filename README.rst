===========
ssm-acquire
===========


.. image:: https://img.shields.io/pypi/v/ssm_acquire.svg
        :target: https://pypi.python.org/pypi/ssm_acquire

.. image:: https://readthedocs.org/projects/ssm-acquire/badge/?version=latest
        :target: https://ssm-acquire.readthedocs.io/en/latest/?badge=latest
        :alt: Documentation Status

A python module for orchestrating content acquisitions and analysis via amazon ssm.  Note:  This is a pre-release.

* Free software: MPL 2.0 License
* Documentation: https://ssm-acquire.readthedocs.io.

Features
--------

* Acquire memory from a linux instance to an S3 bucket using SSM.
* Interrogate an instance for top-10 IOCs using OSQuery and save the jsonified output.
* Analyze a memory sample on a machine using docker.
* Create a rekall profile using an instance as a build target running the Amazon SSM Agent.


Usage
--------

Sample Cli Usage
^^^^^^^^^^^^^^^^^
::

    pip install ssm_acquire
    Usage: ssm_acquire [OPTIONS]

    ssm_acquire a rapid evidence preservation tool for Amazon EC2.

    Options:
      --instance_id TEXT  The instance you would like to operate on.
      --region TEXT       The aws region where the instance can be found.
      --build             Specify if you would like to build a rekall profile with
                          this capture.
      --acquire           Use linpmem to acquire a memory sample from the system
                          in question.
      --interrogate       Use OSQuery binary to preserve top 10 type queries for
                          rapid forensics.
      --analyze           Use docker and rekall to autoanalyze the memory capture.
      --deploy            Create a lambda function with a handler to take events
                          from AWS GuardDuty.
      --help              Show this message and exit.

Getting Started
^^^^^^^^^^^^^^^^^

Deploy Responder Role into AWS Account with the CloudFormation Template: cloudformation/responder_role.yml. (Note: this role requires 2FA to assume) This will create a role with the required permissions to run ssm commands on ec2 instances and an s3 bucket to store the memory assets. You will need the bucket name and the ARN of the role in the next step.

Setup a config file in your home directory. It should be named `.threatresponse.ini` There is a sample config file in conf/settings.ini - it has three required parameters.

* mfa_serial_number: the serial number for your MFA device for assuming the role.
* asset_bucket: the name of the bucket to store the assets. This was created in step 1.
* ssm_acquire_role_arn: the ARN of the Responder Role you created in step 1.

``pip install ssm_acquire``

To acquire memory and build a rekall profile from an instance:

``ssm_acquire --instance_id i-xxxxxxxx --region us-west-2 --build --acquire``

You can analyze your memory capture right away with:

``ssm_acquire --instance_id i-xxxxxxx --analyze``

This will analyze the memory dump with the most common rekall plugins: [psaux, pstree, netstat, ifconfig, pidhashtable]
When the analysis is done it will upload the results back to the asset store.


Credits
-------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
