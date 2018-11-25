"""Runs a docker container and more to perform automated analysis of memory dumps."""
import boto3
import docker
import os

from builtins import FileExistsError
from logging import getLogger
from ssm_acquire import common


config = common.get_config()
logger = getLogger(__name__)


class S3Manager(object):
    def __init__(self, credentials, bucket_name):
        self.credentials = credentials
        self.bucket_name = bucket_name
        self.s3_client = None

    def _connect(self):
        if self.s3_client is None:
            logger.info('Intializing an S3 Client.')
            self.s3_client = boto3.client(
                's3',
                aws_access_key_id=self.credentials['Credentials']['AccessKeyId'],
                aws_secret_access_key=self.credentials['Credentials']['SecretAccessKey'],
                aws_session_token=self.credentials['Credentials']['SessionToken']
            )

    def list_objects_for_key(self, object_key):
        self._connect()
        response = self.s3_client.list_objects(
            Bucket=self.bucket_name,
            Prefix=object_key
        )
        return response.get('Contents')

    def create_instance_directory(self, instance_id):
        try:
            os.mkdir('/tmp/{}'.format(instance_id))
        except FileExistsError:
            pass

    def get_files(self, object_keys):
        self._connect()
        for object_key in object_keys:
            logger.info('Attempting download of: {}'.format(object_key))
            response = self.s3_client.get_object(
                Bucket=self.bucket_name,
                Key=object_key.get('Key')
            )
            fh = open('/tmp/{}'.format(object_key.get('Key')), 'wb')
            fh.write(response['Body'].read())
            fh.close()
            logger.info('File retrieval complete for: {}'.format(object_key))

    def put_file(self, file_path, instance_id):
        self._connect()
        logger.info('Uploading result: {} from file_path: {}'.format(file_path.split('/')[3], file_path))
        object_key = '{}/{}'.format(instance_id, file_path.split('/')[3])
        with open(file_path, 'rb') as data:
            self.s3_client.upload_fileobj(data, self.bucket_name, object_key)


class RekallManager(object):
    def __init__(self, instance_id, credentials):
        self.credentials = credentials
        self.instance_id = instance_id
        self.bucket_name = config('asset_bucket', namespace='ssm_acquire')

        self.client = docker.from_env()
        self.docker_image = 'threatresponse/rekall:latest'
        self.rekall_plugins = [
            'psaux',
            'pstree',
            'netstat',
            'ifconfig',
            'pidhashtable'
        ]

    def download_incident_data(self):
        temp_dir = '/tmp/{}'.format(self.instance_id)
        if os.path.isdir(temp_dir) and len(os.listdir(temp_dir)) != 0:
            logger.info('Temp directory already exists.  Skipping re: fetch.')
            result = os.listdir(temp_dir)
        else:
            logger.info('Attempting to download incident data.')
            s3_manager = S3Manager(self.credentials, self.bucket_name)
            s3_manager.create_instance_directory(self.instance_id)
            keys = s3_manager.list_objects_for_key(self.instance_id)
            result = s3_manager.get_files(keys)
        return result

    def _get_rekall_profile_name(self):
        for file_name in os.listdir('/tmp/{}'.format(self.instance_id)):
            if file_name.endswith('.zip'):
                return file_name

    def _run_a_container(
        self,
        command,
        volumes
    ):
        return self.client.containers.run(
            image=self.docker_image,
            command=command,
            detach=True,
            volumes=volumes
        )

    def pull_rekall_image(self):
        return self.client.images.pull(self.docker_image)

    def run_yara_scan(self):
        yara_file_dir = config('yara_file_dir', namespace='ssm_acquire', default='~/.yarafiles')
        rekall_profile_name = self._get_rekall_profile_name()
        if os.path.isdir(yara_file_dir) and len(os.listdir(yara_file_dir)) != 0:
            for yara_file in os.listdir(yara_file_dir):
                plugin = 'yarascan'
                additional_arg = '--yara_file /opt/yarascan/{}'.format(yara_file)
                command = 'rekall -f /files/capture.aff4 --profile /files/{}json {} {} \
                        --format=json --output=/files/{}-{}-output.json'.format(
                    rekall_profile_name.split('zip')[0],
                    plugin,
                    additional_arg,
                    'yara-scan-{}'.format(yara_file),
                    self.instance_id
                )
            container = self._run_a_container(
                command,
                {
                    '/tmp/{}'.format(self.instance_id): {'bind': '/files'.format(self.instance_id), 'mode': 'rw'},
                    '{}'.format(yara_file_dir): {'bind': '/opt/yarascan', 'mode': 'rw'},
                }
            )

            logger.info('Waiting for yarascan to exit.')
            container.wait(timeout=600)
            print(container.logs())
            container.remove()
        else:
            logger.info('No yara files found.  Skipping yarascan.')

    def run_rekall_plugins(self):
        # Build the json version of the rekall profile first
        rekall_profile_name = self._get_rekall_profile_name()

        logger.info('Attempting to convert the zip of the rekall profile to json'.format(rekall_profile_name))
        command = 'rekall convert_profile {} {}json'.format(
            rekall_profile_name,
            rekall_profile_name.split('zip')[0]
        )
        volumes = {
            '/tmp/{}'.format(self.instance_id):
                {'bind': '/files', 'mode': 'rw'}
        }
        container = self._run_a_container(command, volumes)
        container.stop()
        container.remove()
        logger.info('The rekall profile was converted from a zip file to a json file.')
        logger.info('Begin analysis of the memory sample for the following plugins: {}'.format(self.rekall_plugins))

        plugin_containers = []
        for plugin in self.rekall_plugins:
            logger.info('Running the following plugin: {} on capture.aff4.'.format(plugin))
            command = 'rekall -f /files/capture.aff4 --profile /files/{}json {} \
                    --format=json --output=/files/{}-{}-output.json'.format(
                rekall_profile_name.split('zip')[0],
                plugin,
                plugin,
                self.instance_id
            )
            volumes = {
                '/tmp/{}'.format(self.instance_id): {'bind': '/files', 'mode': 'rw'}
            }
            container = self._run_a_container(command, volumes)
            plugin_containers.append(
                {
                    'plugin': plugin,
                    'container': container
                }
            )

        logs = []
        s3_manager = S3Manager(self.credentials, self.bucket_name)

        for container in plugin_containers:
            # For some reason .status is an object property
            logger.info('Waiting for analysis to complete on: {}'.format(container['plugin']))
            container['container'].wait(timeout=600)
            logs.append(container['container'].logs())
            container['container'].remove()

        for plugin in self.rekall_plugins:
            logger.info('Uploading results for plugin: {}'.format(plugin))
            s3_manager.put_file(
                '/tmp/{}/{}-{}-output.json'.format(self.instance_id, plugin, self.instance_id), self.instance_id
            )

        self.run_yara_scan()

        logger.info('Rekall plugin run complete.')
        return logs


class NativeRekall(object):
    def __init__(self, object_key):
        self.object_key = object_key
