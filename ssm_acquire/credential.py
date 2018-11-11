# -*- coding: utf-8 -*-
import boto3
from logging import getLogger
from prompt_toolkit import prompt

from ssm_acquire.common import get_config


config = get_config()
logger = getLogger(__name__)


class StsManager(object):
    def __init__(self, region_name, limited_scope_policy):
        self.boto_session = boto3.session.Session(region_name=region_name)
        self.sts_client = self.boto_session.client('sts')
        self.limited_scope_policy = limited_scope_policy

    def auth(self):
        if self._should_mfa() and self._should_assume_role():
            logger.info(
                'Assuming the response role using mfa. role: {}, mfa: {}'.format(
                    config('ssm_acquire_role_arn', namespace='ssm_acquire'),
                    config('mfa_serial_number', namespace='ssm_acquire', default='None')
                )
            )
            return self.assume_role_with_mfa(self.sts_client, config('ssm_acquire_role_arn', namespace='ssm_acquire'))
        elif self._should_mfa() and not self._should_assume_role():
            logger.info(
                'Assume role not specificed in the threatresponse.ini genetating sesssion token with mfa. mfa: {}.'.format(
                    config('mfa_serial_number', namespace='ssm_acquire', default='None')
                )
            )
            return self.get_session_token_with_mfa(self.sts_client)
        elif self._should_assume_role() and not self._should_mfa():
            logger.info(
                'Assuming the response role. role: {}'.format(
                    config('ssm_acquire_role_arn', namespace='ssm_acquire'),
                    config('mfa_serial_number', namespace='ssm_acquire', default='None')
                )
            )
            return self.assume_role(self.sts_client, config('ssm_acquire_role_arn', namespace='ssm_acquire'))
        else:
            logger.info(
                'Assume role not specificed in the threatresponse.ini genetating sesssion token using current credials.'.format(
                    config('mfa_serial_number', namespace='ssm_acquire', default='None')
                )
            )
            return self.get_session_token()

    def _should_mfa(self):
        if config('mfa_serial_number', namespace='ssm_acquire', default='None') != 'None':
            return True
        else:
            return False

    def _should_assume_role(self):
        if config('ssm_acquire_role_arn', namespace='ssm_acquire', default='None') != 'None':
            return True
        else:
            return False

    def get_session_token_with_mfa(self, client):
        token_code = prompt('Please enter your MFA Token: ')
        response = client.get_session_token(
            DurationSeconds=config('assume_role_session_duration', default='3600', namespace='ssm_acquire'),
            SerialNumber=config('mfa_serial_number', namespace='ssm_acquire', default='None'),
            TokenCode=token_code
        )
        return response

    def get_session_token(self, client):
        response = client.get_session_token(
            DurationSeconds=config('assume_role_session_duration', default='3600', namespace='ssm_acquire')
        )
        return response

    def assume_role(self, client, role_arn):
        response = client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='ssm-acquire',
            DurationSeconds=3600,
            Policy=self.limited_scope_policy
        )
        return response

    def assume_role_with_mfa(self, client, role_arn):
        token_code = prompt('Please enter your MFA Token: ')
        response = client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='ssm-acquire',
            DurationSeconds=3600,
            SerialNumber=config('mfa_serial_number', namespace='ssm_acquire', default='None'),
            TokenCode=token_code,
            Policy=self.limited_scope_policy
        )
        return response
