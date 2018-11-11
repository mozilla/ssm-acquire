#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `ssm_acquire` package."""

from click.testing import CliRunner
from moto import mock_sts

@mock_sts
def test_command_line_interface():
    from ssm_acquire import cli
    """Test the CLI."""
    runner = CliRunner()
    result = runner.invoke(cli.main)
    assert result.exit_code == 0
    help_result = runner.invoke(cli.main, ['--help'])
    assert help_result.exit_code == 0
    assert help_result.output is not None
