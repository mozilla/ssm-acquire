import boto3
from moto import mock_s3


class TestAnalyze(object):
    def setup(self):
        fh = open('tests/fixtures/capture.aff4', 'rb')
        self.memory_dump = fh.read()
        fh.close()

        fh = open('tests/fixtures/4.14.72-73.55.amzn2.x86_64.zip', 'rb')
        self.rekall_profile = fh.read()
        fh.close()

        fh = open('tests/fixtures/interrogation.log')
        self.interrogation_log = fh.read()
        fh.close()

    @mock_s3
    def test_s3_manager(self):
        s3_client = boto3.client('s3')
        s3_client.create_bucket(
            ACL='private',
            Bucket='dummy-bucket'
        )
        from ssm_acquire import analyze
        s3_manager = analyze.S3Manager(credentials=None, bucket_name='dummy-bucket')
        s3_manager.s3_client = s3_client
        instance_id = 'i-xxx'
        s3_client.put_object(
            Body=self.memory_dump, Bucket='dummy-bucket', Key='{}/{}'.format(instance_id, 'capture.aff4')
        )
        s3_client.put_object(
            Body=self.rekall_profile, Bucket='dummy-bucket', Key='{}/{}'.format(
                instance_id, '4.14.72-73.55.amzn2.x86_64.zip'
            )
        )
        s3_client.put_object(
            Body=self.interrogation_log, Bucket='dummy-bucket', Key='{}/{}'.format(
                instance_id, 'interrogation.log'
            )
        )

        files_for_case = s3_manager.list_objects_for_key(instance_id)
        assert files_for_case is not None
        s3_manager.create_instance_directory(instance_id)
        s3_manager.get_files(files_for_case)

    def test_docker_analysis(self):
        from ssm_acquire import analyze

        analyzer_with_docker = analyze.RekallManager(instance_id='i-xxx', credentials=None)
        analyzer_with_docker.download_incident_data()
        result = analyzer_with_docker.pull_rekall_image()
        assert result is not None
        assert analyzer_with_docker is not None

        result = analyzer_with_docker.run_rekall_plugins()
        assert result is not None
