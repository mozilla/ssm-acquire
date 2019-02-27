import os
import json
import yaml
from everett.ext.inifile import ConfigIniEnv
from everett.manager import ConfigManager
from everett.manager import ConfigOSEnv
from jinja2 import Template
from logging import getLogger


logger = getLogger(__name__)


def get_config():
    return ConfigManager(
        [
            ConfigIniEnv([
                os.environ.get('THREATRESPONSE_INI'),
                '~/.threatresponse.ini',
                '/etc/threatresponse.ini'
            ]),
            ConfigOSEnv()
        ]
    )


def load_acquire():
    this_path = os.path.abspath(os.path.dirname(__file__))
    path = os.path.join(this_path, "acquire-plans/linpmem.yml")
    return yaml.safe_load(open(path))


def load_transfer(credentials, instance_id):
    this_path = os.path.abspath(os.path.dirname(__file__))
    path = os.path.join(this_path, "transfer-plans/linpmem.yml.j2")
    config = get_config()

    fh = open(path)
    template_contents = fh.read()
    fh.close()
    s3_bucket = config('asset_bucket', namespace='ssm_acquire')
    jinja_template = Template(template_contents)
    transfer_plan = jinja_template.render(
        ssm_acquire_access_key=credentials['Credentials']['AccessKeyId'],
        ssm_acquire_secret_key=credentials['Credentials']['SecretAccessKey'],
        ssm_acquire_session_token=credentials['Credentials']['SessionToken'],
        ssm_acquire_s3_bucket=s3_bucket,
        ssm_acquire_instance_id=instance_id

    )
    return yaml.safe_load(transfer_plan)


def load_build(credentials, instance_id):
    this_path = os.path.abspath(os.path.dirname(__file__))
    path = os.path.join(this_path, "build-plans/linpmem.yml.j2")
    config = get_config()

    fh = open(path)
    template_contents = fh.read()
    fh.close()
    s3_bucket = config('asset_bucket', namespace='ssm_acquire')
    jinja_template = Template(template_contents)
    build_plan = jinja_template.render(
        ssm_acquire_access_key=credentials['Credentials']['AccessKeyId'],
        ssm_acquire_secret_key=credentials['Credentials']['SecretAccessKey'],
        ssm_acquire_session_token=credentials['Credentials']['SessionToken'],
        ssm_acquire_s3_bucket=s3_bucket,
        ssm_acquire_instance_id=instance_id

    )
    return yaml.safe_load(build_plan)


def load_interrogate(credentials, instance_id):
    this_path = os.path.abspath(os.path.dirname(__file__))
    path = os.path.join(this_path, "interrogate-plans/osquery.yml.j2")
    config = get_config()

    fh = open(path)
    template_contents = fh.read()
    fh.close()
    s3_bucket = config('asset_bucket', namespace='ssm_acquire')
    jinja_template = Template(template_contents)
    interrogate_plan = jinja_template.render(
        ssm_acquire_access_key=credentials['Credentials']['AccessKeyId'],
        ssm_acquire_secret_key=credentials['Credentials']['SecretAccessKey'],
        ssm_acquire_session_token=credentials['Credentials']['SessionToken'],
        ssm_acquire_s3_bucket=s3_bucket,
        ssm_acquire_instance_id=instance_id

    )
    return yaml.safe_load(interrogate_plan)


def load_policy():
    this_path = os.path.abspath(os.path.dirname(__file__))
    path = os.path.join(this_path, "polices/instance-scoped-policy.yml")
    return yaml.safe_load(open(path))


def generate_arn_for_instance(region, instance_id):
    return 'arn:aws:ec2:*:*:instance/{}'.format(instance_id)


def get_limited_policy(region, instance_id):
    config = get_config()
    policy_template = load_policy()
    instance_arn = generate_arn_for_instance(region, instance_id)
    s3_bucket = config('asset_bucket', namespace='ssm_acquire')
    for permission in policy_template['PolicyDocument']['Statement']:
        if permission['Action'][0] == 's3:PutObject':
            s3_arn = 'arn:aws:s3:::{}/{}'.format(s3_bucket, instance_id)
            s3_keys = 'arn:aws:s3:::{}/{}/*'.format(s3_bucket, instance_id)
            record_index = policy_template['PolicyDocument']['Statement'].index(permission)
            policy_template['PolicyDocument']['Statement'][record_index]['Resource'][0] = s3_arn
            policy_template['PolicyDocument']['Statement'][record_index]['Resource'][1] = s3_keys
        elif permission['Action'][0].startswith('ssm:Send'):
            record_index = policy_template['PolicyDocument']['Statement'].index(permission)
            policy_template['PolicyDocument']['Statement'][record_index]['Resource'][1] = instance_arn
        elif permission['Sid'] == 'STMT4':
            s3_arn = 'arn:aws:s3:::{}'.format(s3_bucket)
            s3_keys = 'arn:aws:s3:::{}/*'.format(s3_bucket)
            record_index = policy_template['PolicyDocument']['Statement'].index(permission)
            policy_template['PolicyDocument']['Statement'][record_index]['Resource'][0] = s3_arn
            policy_template['PolicyDocument']['Statement'][record_index]['Resource'][1] = s3_keys
    statements = json.dumps(policy_template['PolicyDocument'])
    logger.info('Limited scope role generated for assumeRole: {}'.format(statements))
    return statements


def run_command(client, commands, instance_id):
    """Run an ssm command.  Return the boto3 response."""
    # XXX TBD add a test to see if another invocation is pending and raise if waiting.
    response = client.send_command(
        InstanceIds=[instance_id],
        DocumentName='AWS-RunShellScript',
        Comment='Incident response step execution for: {}'.format(instance_id),
        Parameters={
            "commands": commands
        }
    )
    return response


def check_status(client, response, instance_id):
    logger.debug('Attempting to retrieve status for command_id: {}'.format(response['Command']['CommandId']))
    response = client.get_command_invocation(
        CommandId=response['Command']['CommandId'],
        InstanceId=instance_id
    )

    if response['Status'] == 'Pending':
        return None
    if response['Status'] == 'InProgress':
        return None
    if response['Status'] == 'Delayed':
        return None
    if response['Status'] == 'Cancelling':
        return None
    return response['Status']
