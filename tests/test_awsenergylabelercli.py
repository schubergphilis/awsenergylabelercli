#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: test_awsenergylabelercli.py
#
# Copyright 2021 Theodoor Scholte, Costas Tyfoxylos, Jenda Brands
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to
#  deal in the Software without restriction, including without limitation the
#  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#  sell copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#  DEALINGS IN THE SOFTWARE.
#

"""
test_awsenergylabelercli
----------------------------------
Tests for `awsenergylabelercli` module.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import argparse
import contextlib
import io
import json
import os
import sys
import unittest

from pathlib import Path

from awsenergylabelercli import get_arguments, get_parser
from awsenergylabelercli.validators import (character_delimited_list_variable,
                                            environment_variable_boolean,
                                            positive_integer,
                                            json_string,
                                            aws_account_id)
from awsenergylabelerlib import (SECURITY_HUB_ACTIVE_REGIONS,
                                 DEFAULT_SECURITY_HUB_FRAMEWORKS,
                                 SecurityHub,
                                 ACCOUNT_THRESHOLDS,
                                 ZONE_THRESHOLDS)


@contextlib.contextmanager
def captured_output():
    new_out, new_err = io.StringIO(), io.StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = new_out, new_err
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_out, old_err


def get_parsing_error_message(method_name, arguments):
    with captured_output() as (out, err):
        try:
            method_name(arguments)
        except SystemExit:
            pass
    err.seek(0)
    return err.read().split('error:')[1].strip()


__author__ = '''Theodoor Scholte <tscholte@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''11-11-2021'''
__copyright__ = '''Copyright 2021, Theodoor Scholte'''
__credits__ = ["Theodoor Scholte", "Costas Tyfoxylos", "Jenda Brands"]
__license__ = '''MIT'''
__maintainer__ = '''Theodoor Scholte'''
__email__ = '''<tscholte@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

MINIMUM_REQUIRED_ARGUMENTS = ['-r', 'eu-west-1', '-o', 'ORG']


class TestAwsenergylabelercli(unittest.TestCase):

    def setUp(self):
        """
        Test set up

        This is where you can setup things that you use throughout the tests. This method is called before every test.
        """
        pass

    def tearDown(self):
        """
        Test tear down

        This is where you should tear down what you've setup in setUp before. This method is called after every test.
        """
        pass


class TestValidators(unittest.TestCase):

    def test_character_delimited_list_variable_pipe_character(self):
        values = 'alice|bob|jack'
        self.assertTrue(character_delimited_list_variable(values) == ['alice', 'bob', 'jack'])

    def test_character_delimited_list_variable_comma_character(self):
        values = 'alice,bob,jack'
        self.assertTrue(character_delimited_list_variable(values) == ['alice', 'bob', 'jack'])

    def test_character_delimited_list_variable_space_character(self):
        values = 'alice bob jack'
        self.assertTrue(character_delimited_list_variable(values) == ['alice', 'bob', 'jack'])

    def test_character_delimited_list_variable_mixed_characters(self):
        values = 'alice,bob|jack more'
        self.assertTrue(character_delimited_list_variable(values) == ['alice', 'bob', 'jack', 'more'])

    def test_character_delimited_list_single_value(self):
        values = 'alice'
        self.assertTrue(character_delimited_list_variable(values) == 'alice')

    def test_environment_variable_boolean_true_values(self):
        for value in ['t', 'T', 'true', 'True', 1, '1', 'TRUE']:
            self.assertTrue(environment_variable_boolean(value))

    def test_environment_variable_boolean_false_values(self):
        for value in ['f', 'TruE', 'garbage']:
            self.assertFalse(environment_variable_boolean(value))

    def test_positive_integer_none_value(self):
        self.assertIsNone(positive_integer(None))

    def test_positive_integer_valid_values(self):
        self.assertTrue(positive_integer('1') == 1)
        self.assertTrue(positive_integer(1) == 1)
        self.assertTrue(positive_integer('14') == 14)

    def test_positive_integer_invalid_value(self):
        self.assertRaises(argparse.ArgumentTypeError, positive_integer, 'a')
        self.assertRaises(argparse.ArgumentTypeError, positive_integer, '-5')
        self.assertRaises(argparse.ArgumentTypeError, positive_integer, -2)

    def test_json_string_none_value(self):
        self.assertIsNone(json_string(None))

    def test_json_string_valid_values(self):
        self.assertTrue(json_string('{"a": 1}') == {'a': 1})
        self.assertTrue(json_string('{"a": ["f", "a"], "b": {"a": 3}}') == {'a': ['f', 'a'], 'b': {'a': 3}})

    def test_json_string_invalid_values(self):
        self.assertRaises(argparse.ArgumentTypeError, json_string, 'adfad')

    def test_aws_account_id(self):
        self.assertRaises(argparse.ArgumentTypeError, aws_account_id, 'adfad')


class TestRegion(unittest.TestCase):

    def setUp(self):
        """
        Test set up

        This is where you can setup things that you use throughout the tests. This method is called before every test.
        """
        self.missing_arguments_message = 'the following arguments are required: --region/-r'
        self.error_message = ('argument --region/-r: Region {invalid_region} provided does not seem to be valid, valid ' \
                              'regions are {SECURITY_HUB_ACTIVE_REGIONS}.')

    def test_missing_region(self):
        self.assertTrue(get_parsing_error_message(get_arguments, []) == self.missing_arguments_message)

    def test_invalid_region(self):
        invalid_region = 'bob'
        error_message = self.error_message.format(invalid_region=invalid_region,
                                                  SECURITY_HUB_ACTIVE_REGIONS=SECURITY_HUB_ACTIVE_REGIONS)
        self.assertTrue(get_parsing_error_message(get_arguments, ['-r', invalid_region]) == error_message)

    def test_invalid_long_region(self):
        invalid_region = 'bob'
        error_message = self.error_message.format(invalid_region=invalid_region,
                                                  SECURITY_HUB_ACTIVE_REGIONS=SECURITY_HUB_ACTIVE_REGIONS)
        self.assertTrue(get_parsing_error_message(get_arguments, ['--region', invalid_region]) == error_message)

    def test_valid_region_argument_provided(self):
        valid_region = 'eu-west-1'
        args = get_arguments(['-r', valid_region, '-z', 'DUMMY_ZONE_NAME'])
        self.assertTrue(args.region == valid_region)

    def test_valid_region_long_argument_provided(self):
        valid_region = 'eu-west-1'
        args = get_arguments(['--region', valid_region, '-z', 'DUMMY_ZONE_NAME'])
        self.assertTrue(args.region == valid_region)

    def test_valid_region_env_var_provided(self):
        valid_region = 'eu-west-1'
        os.environ['AWS_LABELER_REGION'] = valid_region
        args = get_arguments(['-z', 'DUMMY_ZONE_NAME'])
        del os.environ['AWS_LABELER_REGION']
        self.assertTrue(args.region == valid_region)

    def test_invalid_region_env_var_provided(self):
        invalid_region = 'bob'
        os.environ['AWS_LABELER_REGION'] = invalid_region
        error_message = self.error_message.format(invalid_region=invalid_region,
                                                  SECURITY_HUB_ACTIVE_REGIONS=SECURITY_HUB_ACTIVE_REGIONS)
        parsing_error_message = get_parsing_error_message(get_arguments, ['-z', 'DUMMY_ZONE_NAME'])
        del os.environ['AWS_LABELER_REGION']
        self.assertTrue(parsing_error_message == error_message)


class TestZone(unittest.TestCase):
    def setUp(self):
        """
        Test set up

        This is where you can set up things that you use throughout the tests. This method is called before every test.
        """
        self.missing_arguments_message = ('one of the arguments --organizations-zone-name/-o '
                                          '--audit-zone-name/-z --single-account-id/-s is required')
        self.mutually_exclusive_arguments_message = ('arguments --organizations-zone-name/-o --audit-zone-name/-z '
                                                     '--single-account-id/-s are mutually exclusive')


class TestOrganization(TestZone):

    def test_missing_organization_name(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1'])
        self.assertTrue(parsing_error_message == self.missing_arguments_message)

    def test_valid_organization_name_argument_provided(self):
        valid_org_name = 'TEST_ORG'
        args = get_arguments(['-r', 'eu-west-1', '-o', valid_org_name])
        self.assertTrue(args.organizations_zone_name == valid_org_name)

    def test_valid_organization_name_long_argument_provided(self):
        valid_org_name = 'TEST_ORG'
        args = get_arguments(['-r', 'eu-west-1', '--organizations-zone-name', valid_org_name])
        self.assertTrue(args.organizations_zone_name == valid_org_name)

    def test_valid_organization_name_env_var_provided(self):
        valid_org_name = 'TEST_ORG'
        os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME'] = valid_org_name
        args = get_arguments(['-r', 'eu-west-1'])
        del os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME']
        self.assertTrue(args.organizations_zone_name == valid_org_name)

    def test_valid_organization_name_env_var_argument_provided(self):
        valid_org_name = 'TEST_ORG'
        os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME'] = valid_org_name
        args = get_arguments(['-r', 'eu-west-1', '-o', valid_org_name])
        del os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME']
        self.assertTrue(args.organizations_zone_name == valid_org_name)

    def test_valid_organization_name_env_var_long_argument_provided(self):
        valid_org_name = 'TEST_ORG'
        os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME'] = valid_org_name
        args = get_arguments(['-r', 'eu-west-1', '--organizations-zone-name', valid_org_name])
        del os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME']
        self.assertTrue(args.organizations_zone_name == valid_org_name)

    def test_mutually_exclusive_with_audit_zone_both_as_arguments(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '-o', 'ORG_NAME',
                                                                          '-z', 'ZONE_NAME'])
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_audit_zone_both_as_long_arguments(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '--organizations-zone-name', 'ORG_NAME',
                                                                          '--audit-zone-name', 'ZONE_NAME'])
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_audit_zone_as_long_argument_org_as_argument(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '-o', 'ORG_NAME',
                                                                          '--audit-zone-name', 'ZONE_NAME'])
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_audit_zone_as_argument_org_as_long_argument(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '--organizations-zone-name', 'ORG_NAME',
                                                                          '-z', 'ZONE_NAME'])
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_audit_zone_and_single_and_org_as_arguments(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '-o', 'ORG_NAME',
                                                                          '-z', 'ZONE_NAME',
                                                                          '-s', '123456789012'])
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_audit_zone_and_single_and_org_as_long_arguments(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '--organizations-zone-name', 'ORG_NAME',
                                                                          '--audit-zone-name', 'ZONE_NAME',
                                                                          '--single-account-id', '123456789012'])
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_audit_zone_as_argument_and_single_and_org_as_long_arguments(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '--organizations-zone-name', 'ORG_NAME',
                                                                          '-z', 'ZONE_NAME',
                                                                          '--single-account-id', '123456789012'])
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_audit_zone_and_org_as_long_arguments_and_single_as_argument(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '--organizations-zone-name', 'ORG_NAME',
                                                                          '--audit-zone-name', 'ZONE_NAME',
                                                                          '-s', '123456789012'])
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_audit_zone_as_long_argument_and_org_and_single_as_arguments(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '-o', 'ORG_NAME',
                                                                          '--audit-zone-name', 'ZONE_NAME',
                                                                          '-s', '123456789012'])
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_audit_zone_and_single_as_argument_and_org_as_long_argument(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '--organizations-zone-name', 'ORG_NAME',
                                                                          '-z', 'ZONE_NAME',
                                                                          '-s', '123456789012'])
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_audit_zone_and_org_as_argument_and_single_as_long_argument(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '-o', 'ORG_NAME',
                                                                          '-z', 'ZONE_NAME',
                                                                          '--single-account-id', '123456789012'])
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_single_account_and_org_as_arguments(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '-o', 'ORG_NAME',
                                                                          '-s', '123456789012'])
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_single_account_and_org_as_long_arguments(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '--organizations-zone-name', 'ORG_NAME',
                                                                          '--single-account-id', '123456789012'])
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_single_account_as_argument_and_org_as_long_argument(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '--organizations-zone-name', 'ORG_NAME',
                                                                          '-s', '123456789012'])
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_single_account_as_long_argument_and_org_as_argument(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '-o', 'ORG_NAME',
                                                                          '--single-account-id', '123456789012'])
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_audit_zone_as_argument_and_organization_as_env_var(self):
        valid_org_name = 'VALID_ORG'
        os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME'] = valid_org_name
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1', '-z', 'ZONE_NAME'])
        del os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME']
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_audit_zone_as_long_argument_and_organization_as_env_var(self):
        valid_org_name = 'VALID_ORG'
        os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME'] = valid_org_name
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '--audit-zone-name', 'ZONE_NAME'])
        del os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME']
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_single_account_as_argument_and_organization_as_env_var(self):
        valid_org_name = 'VALID_ORG'
        os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME'] = valid_org_name
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1', '-s', '123456789012'])
        del os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME']
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_single_account_as_long_argument_and_organization_as_env_var(self):
        valid_org_name = 'VALID_ORG'
        os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME'] = valid_org_name
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '--single-account-id', '123456789012'])
        del os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME']
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_audit_zone_as_env_var_and_org_as_argument(self):
        os.environ['AWS_LABELER_AUDIT_ZONE_NAME'] = 'ZONE_NAME'
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1', '-o', 'ORG_NAME'])
        del os.environ['AWS_LABELER_AUDIT_ZONE_NAME']
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_audit_zone_as_env_var_and_org_as_long_argument(self):
        os.environ['AWS_LABELER_AUDIT_ZONE_NAME'] = 'ZONE_NAME'
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '--organizations-zone-name', 'ORG_NAME'])
        del os.environ['AWS_LABELER_AUDIT_ZONE_NAME']
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_single_account_as_env_var_and_org_as_argument(self):
        os.environ['AWS_LABELER_SINGLE_ACCOUNT_ID'] = '123456789012'
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1', '-o', 'ORG_NAME'])
        del os.environ['AWS_LABELER_SINGLE_ACCOUNT_ID']
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_single_account_as_env_var_and_org_as_long_argument(self):
        os.environ['AWS_LABELER_SINGLE_ACCOUNT_ID'] = '123456789012'
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '--organizations-zone-name', 'ORG_NAME'])
        del os.environ['AWS_LABELER_SINGLE_ACCOUNT_ID']
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)


class TestAuditZone(TestZone):

    def test_missing_audit_zone_name(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1'])
        self.assertTrue(parsing_error_message == self.missing_arguments_message)

    def test_valid_audit_zone_name_argument_provided(self):
        valid_zone_name = 'AUDIT_ZONE'
        args = get_arguments(['-r', 'eu-west-1', '-z', valid_zone_name])
        self.assertTrue(args.audit_zone_name == valid_zone_name)

    def test_valid_audit_zone_name_long_argument_provided(self):
        valid_zone_name = 'AUDIT_ZONE'
        args = get_arguments(['-r', 'eu-west-1', '--audit-zone-name', valid_zone_name])
        self.assertTrue(args.audit_zone_name == valid_zone_name)

    def test_valid_audit_zone_name_env_var_provided(self):
        valid_zone_name = 'AUDIT_ZONE'
        os.environ['AWS_LABELER_AUDIT_ZONE_NAME'] = valid_zone_name
        args = get_arguments(['-r', 'eu-west-1'])
        del os.environ['AWS_LABELER_AUDIT_ZONE_NAME']
        self.assertTrue(args.audit_zone_name == valid_zone_name)

    def test_mutually_exclusive_with_single_account_both_as_arguments(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '-z', 'AUDIT_ZONE',
                                                                          '-s', '123456789012'])
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_single_account_both_as_long_arguments(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '--audit-zone-name', 'AUDIT_ZONE',
                                                                          '--single-account-id', '123456789012'])
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_single_account_as_long_argument_and_audit_zone_as_argument(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '-z', 'AUDIT_ZONE',
                                                                          '--single-account-id', '123456789012'])
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_single_account_as_argument_and_audit_zone_as_long_argument(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '--audit-zone-name', 'AUDIT_ZONE',
                                                                          '-s', '123456789012'])
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_organizations_as_env_var_and_audit_zone_as_argument(self):
        valid_org_name = 'VALID_ORG'
        os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME'] = valid_org_name
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1', '-z', 'AUDIT_ZONE'])
        del os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME']
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_organizations_as_env_var_and_audit_zone_as_long_argument(self):
        valid_org_name = 'VALID_ORG'
        os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME'] = valid_org_name
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '--audit-zone-name', 'AUDIT_ZONE'])
        del os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME']
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_single_account_as_env_var_and_audit_zone_as_argument(self):
        os.environ['AWS_LABELER_SINGLE_ACCOUNT_ID'] = '123456789012'
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1', '-z', 'AUDIT_ZONE'])
        del os.environ['AWS_LABELER_SINGLE_ACCOUNT_ID']
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_single_account_as_env_var_and_audit_zone_as_long_argument(self):
        os.environ['AWS_LABELER_SINGLE_ACCOUNT_ID'] = '123456789012'
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '--audit-zone-name', 'AUDIT_ZONE'])
        del os.environ['AWS_LABELER_SINGLE_ACCOUNT_ID']
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)


class TestSingleAccount(TestZone):

    def setUp(self):
        super(TestSingleAccount, self).setUp()
        self.invalid_single_account = '123456789012a'
        self.invalid_account_id_error_message = (f'argument --single-account-id/-s: Account id '
                                                 f'{self.invalid_single_account} provided does not seem to be valid.')

    def test_missing_single_account(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1'])
        self.assertTrue(parsing_error_message == self.missing_arguments_message)

    def test_invalid_single_account_argument_provided(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '-s', self.invalid_single_account])
        self.assertTrue(parsing_error_message == self.invalid_account_id_error_message)

    def test_invalid_single_account_long_argument_provided(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '--single-account-id',
                                                                          self.invalid_single_account])
        self.assertTrue(parsing_error_message == self.invalid_account_id_error_message)

    def test_valid_single_account_argument_provided(self):
        valid_single_account = '123456789012'
        args = get_arguments(['-r', 'eu-west-1', '-s', valid_single_account])
        self.assertTrue(args.single_account_id == valid_single_account)

    def test_valid_single_account_long_argument_provided(self):
        valid_single_account = '123456789012'
        args = get_arguments(['-r', 'eu-west-1', '--single-account-id', valid_single_account])
        self.assertTrue(args.single_account_id == valid_single_account)

    def test_valid_single_account_id_env_var_provided(self):
        valid_single_account = '123456789012'
        os.environ['AWS_LABELER_SINGLE_ACCOUNT_ID'] = valid_single_account
        args = get_arguments(['-r', 'eu-west-1'])
        del os.environ['AWS_LABELER_SINGLE_ACCOUNT_ID']
        self.assertTrue(args.single_account_id == valid_single_account)

    def test_mutually_exclusive_with_organizations_as_env_var_and_single_as_argument(self):
        valid_org_name = 'VALID_ORG'
        os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME'] = valid_org_name
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1', '-s', '123456789012'])
        del os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME']
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_organizations_as_env_var_and_single_as_long_argument(self):
        valid_org_name = 'VALID_ORG'
        os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME'] = valid_org_name
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '--single-account-id', '123456789012'])
        del os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME']
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_audit_zone_as_env_var_and_single_as_argument(self):
        os.environ['AWS_LABELER_AUDIT_ZONE_NAME'] = 'ZONE_NAME'
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1', '-s', '123456789012'])
        del os.environ['AWS_LABELER_AUDIT_ZONE_NAME']
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_audit_zone_as_env_var_and_single_as_long_argument(self):
        os.environ['AWS_LABELER_AUDIT_ZONE_NAME'] = 'ZONE_NAME'
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '--single-account-id', '123456789012'])
        del os.environ['AWS_LABELER_AUDIT_ZONE_NAME']
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)


class TestFrameworks(unittest.TestCase):

    def setUp(self) -> None:
        self.error_message = ('{provided_frameworks} are not valid supported security hub frameworks. Currently '
                              'supported are {frameworks}')

    def test_empty_frameworks(self):
        args = get_arguments(['-r', 'eu-west-1', '-o', 'ORG', '-f', ''])
        self.assertTrue(args.frameworks == [])

    def test_empty_frameworks_with_long_argument(self):
        args = get_arguments(['-r', 'eu-west-1', '-o', 'ORG', '--frameworks', ''])
        self.assertTrue(args.frameworks == [])

    def test_default_frameworks(self):
        args = get_arguments(MINIMUM_REQUIRED_ARGUMENTS)
        self.assertTrue(args.frameworks == DEFAULT_SECURITY_HUB_FRAMEWORKS)

    def test_invalid_frameworks(self):
        frameworks = 'aws-foundational-security-best-practices,bob'
        arguments = ['-r', 'eu-west-1', '-o', 'ORG', '-f', frameworks]
        parser = get_parser()
        error_frameworks = parser.parse_args(arguments).frameworks
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        error_message = self.error_message.format(provided_frameworks=error_frameworks,
                                                  frameworks=SecurityHub.frameworks)
        self.assertTrue(parsing_error_message == error_message)

    def test_invalid_frameworks_with_long_argument(self):
        frameworks = 'aws-foundational-security-best-practices,bob'
        arguments = ['-r', 'eu-west-1', '-o', 'ORG', '--frameworks', frameworks]
        parser = get_parser()
        error_frameworks = parser.parse_args(arguments).frameworks
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        error_message = self.error_message.format(provided_frameworks=error_frameworks,
                                                  frameworks=SecurityHub.frameworks)
        self.assertTrue(parsing_error_message == error_message)

    def test_invalid_frameworks_as_env_var(self):
        os.environ['AWS_LABELER_FRAMEWORKS'] = 'aws-foundational-security-best-practices,bob'
        parser = get_parser()
        error_frameworks = parser.parse_args(MINIMUM_REQUIRED_ARGUMENTS).frameworks
        parsing_error_message = get_parsing_error_message(get_arguments, MINIMUM_REQUIRED_ARGUMENTS)
        del os.environ['AWS_LABELER_FRAMEWORKS']
        error_message = self.error_message.format(provided_frameworks=error_frameworks,
                                                  frameworks=SecurityHub.frameworks)
        self.assertTrue(parsing_error_message == error_message)


class TestAccountIds(unittest.TestCase):

    def setUp(self) -> None:
        self.mutually_exclusive_arguments_message = ('argument --allowed-account-ids/-a: not allowed with argument '
                                                     '--denied-account-ids/-d')
        self.mutually_exclusive_arguments_with_single_message = ('arguments --allowed-account-ids/-a '
                                                                 '--denied-account-ids/-d '
                                                                 '--single-account-id/-s are mutually exclusive')

    def test_mutually_exclusive_account_id_arguments(self):
        arguments = ['-r', 'eu-west-1', '-o', 'ORG', '-a', '123456789012', '-d', '123456789012']
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_account_id_long_arguments(self):
        arguments = ['-r', 'eu-west-1', '-o', 'ORG',
                     '--allowed-account-ids', '123456789012', '--denied-account-ids', '123456789012']
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_allowed_account_id_as_long_argument_and_denied_account_id_as_argument(self):
        arguments = ['-r', 'eu-west-1', '-o', 'ORG', '--allowed-account-ids', '123456789012', '-d', '123456789012']
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_allowed_account_id_as_argument_and_denied_account_id_as_long_argument(self):
        arguments = ['-r', 'eu-west-1', '-o', 'ORG', '-a', '123456789012', '--denied-account-ids', '123456789012']
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_allowed_account_id_with_single_account_arguments(self):
        arguments = ['-r', 'eu-west-1', '-a', '123456789012', '-s', '123456789012']
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_with_single_message)

    def test_mutually_exclusive_account_id_with_single_account_long_arguments(self):
        arguments = ['-r', 'eu-west-1', '-a', '123456789012', '--single-account-id', '123456789012']
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_with_single_message)

    def test_mutually_exclusive_denied_account_id_with_single_account_arguments(self):
        arguments = ['-r', 'eu-west-1', '-d', '123456789012', '-s', '123456789012']
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_with_single_message)

    def test_allowed_account_ids_valid_as_argument(self):
        valid_account_ids = ['123456789012', '234567890123']
        args = get_arguments(['-r', 'eu-west-1', '-o', 'ORG_NAME', '-a', ','.join(valid_account_ids)])
        self.assertTrue(args.allowed_account_ids == valid_account_ids)

    def test_allowed_account_ids_valid_as_long_argument(self):
        valid_account_ids = ['123456789012', '234567890123']
        args = get_arguments(['-r', 'eu-west-1', '-o', 'ORG_NAME',
                              '--allowed-account-ids', ','.join(valid_account_ids)])
        self.assertTrue(args.allowed_account_ids == valid_account_ids)

    def test_allowed_account_ids_valid_as_env_var(self):
        valid_account_ids = ['123456789012', '234567890123']
        os.environ['AWS_LABELER_ALLOWED_ACCOUNT_IDS'] = ','.join(valid_account_ids)
        args = get_arguments(['-r', 'eu-west-1', '-o', 'ORG_NAME'])
        del os.environ['AWS_LABELER_ALLOWED_ACCOUNT_IDS']
        self.assertTrue(args.allowed_account_ids == valid_account_ids)

    def test_allowed_account_ids_invalid_as_argument(self):
        invalid_account_ids = ['a123456789012', '2345678s90123']
        arguments = ['-r', 'eu-west-1', '-o', 'ORG_NAME', '-a', ','.join(invalid_account_ids)]
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        error_message = f'{invalid_account_ids} contains invalid account ids.'
        self.assertTrue(parsing_error_message == error_message)

    def test_allowed_account_ids_invalid_as_long_argument(self):
        invalid_account_ids = ['a123456789012', '2345678s90123']
        arguments = ['-r', 'eu-west-1', '-o', 'ORG_NAME', '--allowed-account-ids', ','.join(invalid_account_ids)]
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        error_message = f'{invalid_account_ids} contains invalid account ids.'
        self.assertTrue(parsing_error_message == error_message)

    def test_allowed_account_ids_invalid_as_env_var(self):
        invalid_account_ids = ['a123456789012', '2345678s90123']
        os.environ['AWS_LABELER_ALLOWED_ACCOUNT_IDS'] = ','.join(invalid_account_ids)
        arguments = ['-r', 'eu-west-1', '-o', 'ORG_NAME']
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        del os.environ['AWS_LABELER_ALLOWED_ACCOUNT_IDS']
        error_message = f'{invalid_account_ids} contains invalid account ids.'
        self.assertTrue(parsing_error_message == error_message)

    def test_denied_account_ids_valid_as_argument(self):
        valid_account_ids = ['123456789012', '234567890123']
        args = get_arguments(['-r', 'eu-west-1', '-o', 'ORG_NAME', '-d', ','.join(valid_account_ids)])
        self.assertTrue(args.denied_account_ids == valid_account_ids)

    def test_denied_account_ids_valid_as_long_argument(self):
        valid_account_ids = ['123456789012', '234567890123']
        args = get_arguments(['-r', 'eu-west-1', '-o', 'ORG_NAME', '--denied-account-ids', ','.join(valid_account_ids)])
        self.assertTrue(args.denied_account_ids == valid_account_ids)

    def test_denied_account_ids_valid_as_env_var(self):
        valid_account_ids = ['123456789012', '234567890123']
        os.environ['AWS_LABELER_DENIED_ACCOUNT_IDS'] = ','.join(valid_account_ids)
        args = get_arguments(['-r', 'eu-west-1', '-o', 'ORG_NAME'])
        del os.environ['AWS_LABELER_DENIED_ACCOUNT_IDS']
        self.assertTrue(args.denied_account_ids == valid_account_ids)

    def test_denied_account_ids_invalid_as_argument(self):
        invalid_account_ids = ['a123456789012', '2345678s90123']
        arguments = ['-r', 'eu-west-1', '-o', 'ORG_NAME', '-d', ','.join(invalid_account_ids)]
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        error_message = f'{invalid_account_ids} contains invalid account ids.'
        self.assertTrue(parsing_error_message == error_message)

    def test_denied_account_ids_invalid_as_long_argument(self):
        invalid_account_ids = ['a123456789012', '2345678s90123']
        arguments = ['-r', 'eu-west-1', '-o', 'ORG_NAME', '--denied-account-ids', ','.join(invalid_account_ids)]
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        error_message = f'{invalid_account_ids} contains invalid account ids.'
        self.assertTrue(parsing_error_message == error_message)

    def test_denied_account_ids_invalid_as_env_var(self):
        invalid_account_ids = ['a123456789012', '2345678s90123']
        os.environ['AWS_LABELER_DENIED_ACCOUNT_IDS'] = ','.join(invalid_account_ids)
        arguments = ['-r', 'eu-west-1', '-o', 'ORG_NAME']
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        del os.environ['AWS_LABELER_DENIED_ACCOUNT_IDS']
        error_message = f'{invalid_account_ids} contains invalid account ids.'
        self.assertTrue(parsing_error_message == error_message)


class TestRegions(unittest.TestCase):

    def setUp(self) -> None:
        self.mutually_exclusive_arguments_message = ('argument --allowed-regions/-ar: not allowed with argument '
                                                     '--denied-regions/-dr')
        self.valid_regions = ['eu-west-1', 'eu-central-1']
        self.invalid_regions = ['eu-west-18', 'bobs-region']

    def test_mutually_exclusive_region_arguments(self):
        arguments = ['-r', 'eu-west-1', '-o', 'ORG', '-ar', 'eu-west-1', '-dr', 'eu-central-1']
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_region_long_arguments(self):
        arguments = ['-r', 'eu-west-1', '-o', 'ORG',
                     '--allowed-regions', 'eu-west-1', '--denied-regions', 'eu-central-1']
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_region_allowed_as_long_argument_denied_as_argument(self):
        arguments = ['-r', 'eu-west-1', '-o', 'ORG',
                     '--allowed-regions', 'eu-west-1', '-dr', 'eu-central-1']
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_region_allowed_as_argument_denied_as_long_argument(self):
        arguments = ['-r', 'eu-west-1', '-o', 'ORG',
                     '-ar', 'eu-west-1', '--denied-regions', 'eu-central-1']
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_allowed_regions_valid_as_argument(self):
        args = get_arguments(['-r', 'eu-west-1', '-o', 'ORG_NAME', '-ar', ','.join(self.valid_regions)])
        self.assertTrue(args.allowed_regions == self.valid_regions)

    def test_allowed_regions_valid_as_long_argument(self):
        args = get_arguments(['-r', 'eu-west-1', '-o', 'ORG_NAME', '--allowed-regions', ','.join(self.valid_regions)])
        self.assertTrue(args.allowed_regions == self.valid_regions)

    def test_allowed_regions_valid_as_env_var(self):
        os.environ['AWS_LABELER_ALLOWED_REGIONS'] = ','.join(self.valid_regions)
        args = get_arguments(['-r', 'eu-west-1', '-o', 'ORG_NAME'])
        del os.environ['AWS_LABELER_ALLOWED_REGIONS']
        self.assertTrue(args.allowed_regions == self.valid_regions)

    def test_allowed_regions_invalid_as_argument(self):
        arguments = ['-r', 'eu-west-1', '-o', 'ORG_NAME', '-ar', ','.join(self.invalid_regions)]
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        error_message = f'{self.invalid_regions} contains invalid regions.'
        self.assertTrue(parsing_error_message == error_message)

    def test_allowed_regions_invalid_as_long_argument(self):
        arguments = ['-r', 'eu-west-1', '-o', 'ORG_NAME', '--allowed-regions', ','.join(self.invalid_regions)]
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        error_message = f'{self.invalid_regions} contains invalid regions.'
        self.assertTrue(parsing_error_message == error_message)

    def test_allowed_regions_invalid_as_env_var(self):
        os.environ['AWS_LABELER_ALLOWED_REGIONS'] = ','.join(self.invalid_regions)
        arguments = ['-r', 'eu-west-1', '-o', 'ORG_NAME']
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        del os.environ['AWS_LABELER_ALLOWED_REGIONS']
        error_message = f'{self.invalid_regions} contains invalid regions.'
        self.assertTrue(parsing_error_message == error_message)

    def test_denied_regions_valid_as_argument(self):
        args = get_arguments(['-r', 'eu-west-1', '-o', 'ORG_NAME', '-dr', ','.join(self.valid_regions)])
        self.assertTrue(args.denied_regions == self.valid_regions)

    def test_denied_regions_valid_as_long_argument(self):
        args = get_arguments(['-r', 'eu-west-1', '-o', 'ORG_NAME', '--denied-regions', ','.join(self.valid_regions)])
        self.assertTrue(args.denied_regions == self.valid_regions)

    def test_denied_regions_valid_as_env_var(self):
        os.environ['AWS_LABELER_DENIED_REGIONS'] = ','.join(self.valid_regions)
        args = get_arguments(['-r', 'eu-west-1', '-o', 'ORG_NAME'])
        del os.environ['AWS_LABELER_DENIED_REGIONS']
        self.assertTrue(args.denied_regions == self.valid_regions)

    def test_denied_regions_invalid_as_argument(self):
        arguments = ['-r', 'eu-west-1', '-o', 'ORG_NAME', '-dr', ','.join(self.invalid_regions)]
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        error_message = f'{self.invalid_regions} contains invalid regions.'
        self.assertTrue(parsing_error_message == error_message)

    def test_denied_regions_invalid_as_long_argument(self):
        arguments = ['-r', 'eu-west-1', '-o', 'ORG_NAME', '--denied-regions', ','.join(self.invalid_regions)]
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        error_message = f'{self.invalid_regions} contains invalid regions.'
        self.assertTrue(parsing_error_message == error_message)

    def test_denied_regions_invalid_as_env_var(self):
        os.environ['AWS_LABELER_DENIED_REGIONS'] = ','.join(self.invalid_regions)
        arguments = ['-r', 'eu-west-1', '-o', 'ORG_NAME']
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        del os.environ['AWS_LABELER_DENIED_REGIONS']
        error_message = f'{self.invalid_regions} contains invalid regions.'
        self.assertTrue(parsing_error_message == error_message)


class TestExportArgs(unittest.TestCase):

    def setUp(self) -> None:
        self.valid_local_paths = ['test', f'{os.sep}test', f'.{os.sep}test']
        self.invalid_local_paths = ['s4://test', '//:/test', r'//\:\//test', 'html://test']
        self.valid_s3_paths = ['s3://something/other', 's3://test']
        self.invalid_s3_paths = ['s5:/something/other', 'https://test']
        self.error_message = '{provided_path} is an invalid export location. Example --export-path /a/directory or ' \
                             '--export-path s3://mybucket location'

    def test_export_valid_local_path_argument_provided(self):
        for local_path in self.valid_local_paths:
            arguments = ['-r', 'eu-west-1', '-o', 'ORG', '-p', local_path]
            args = get_arguments(arguments)
            self.assertTrue(args.export_path == local_path)

    def test_export_valid_local_path_long_argument_provided(self):
        for local_path in self.valid_local_paths:
            arguments = ['-r', 'eu-west-1', '-o', 'ORG', '--export-path', local_path]
            args = get_arguments(arguments)
            self.assertTrue(args.export_path == local_path)

    def test_export_valid_local_path_env_var_provided(self):
        for local_path in self.valid_local_paths:
            os.environ['AWS_LABELER_EXPORT_PATH'] = local_path
            args = get_arguments(MINIMUM_REQUIRED_ARGUMENTS)
            self.assertTrue(args.export_path == local_path)
            del os.environ['AWS_LABELER_EXPORT_PATH']

    def test_export_invalid_local_path_argument_provided(self):
        for local_path in self.invalid_local_paths:
            arguments = ['-r', 'eu-west-1', '-o', 'ORG', '-p', local_path]
            parsing_error_message = get_parsing_error_message(get_arguments, arguments)
            error_message = f'{local_path} is an invalid export location. Example --export-path /a/directory or ' \
                            f'--export-path s3://mybucket location'
            self.assertTrue(parsing_error_message == error_message)

    def test_export_invalid_local_path_long_argument_provided(self):
        for local_path in self.invalid_local_paths:
            arguments = ['-r', 'eu-west-1', '-o', 'ORG', '--export-path', local_path]
            parsing_error_message = get_parsing_error_message(get_arguments, arguments)
            error_message = f'{local_path} is an invalid export location. Example --export-path /a/directory or ' \
                            f'--export-path s3://mybucket location'
            self.assertTrue(parsing_error_message == error_message)

    def test_export_invalid_local_path_env_var_provided(self):
        for local_path in self.invalid_local_paths:
            os.environ['AWS_LABELER_EXPORT_PATH'] = local_path
            parsing_error_message = get_parsing_error_message(get_arguments, MINIMUM_REQUIRED_ARGUMENTS)
            error_message = f'{local_path} is an invalid export location. Example --export-path /a/directory or ' \
                            f'--export-path s3://mybucket location'
            self.assertTrue(parsing_error_message == error_message)
            del os.environ['AWS_LABELER_EXPORT_PATH']

    def test_export_valid_s3_path_argument_provided(self):
        for s3_path in self.valid_s3_paths:
            arguments = ['-r', 'eu-west-1', '-o', 'ORG', '-p', s3_path]
            args = get_arguments(arguments)
            self.assertTrue(args.export_path == s3_path)

    def test_export_valid_s3_path_long_argument_provided(self):
        for s3_path in self.valid_s3_paths:
            arguments = ['-r', 'eu-west-1', '-o', 'ORG', '--export-path', s3_path]
            args = get_arguments(arguments)
            self.assertTrue(args.export_path == s3_path)

    def test_export_valid_s3_path_env_var_provided(self):
        for s3_path in self.valid_s3_paths:
            os.environ['AWS_LABELER_EXPORT_PATH'] = s3_path
            args = get_arguments(MINIMUM_REQUIRED_ARGUMENTS)
            self.assertTrue(args.export_path == s3_path)
            del os.environ['AWS_LABELER_EXPORT_PATH']

    def test_export_invalid_s3_path_argument_provided(self):
        for s3_path in self.invalid_s3_paths:
            arguments = ['-r', 'eu-west-1', '-o', 'ORG', '-p', s3_path]
            parsing_error_message = get_parsing_error_message(get_arguments, arguments)
            error_message = f'{s3_path} is an invalid export location. Example --export-path /a/directory or ' \
                            f'--export-path s3://mybucket location'
            self.assertTrue(parsing_error_message == error_message)

    def test_export_invalid_s3_path_long_argument_provided(self):
        for s3_path in self.invalid_s3_paths:
            arguments = ['-r', 'eu-west-1', '-o', 'ORG', '--export-path', s3_path]
            parsing_error_message = get_parsing_error_message(get_arguments, arguments)
            error_message = f'{s3_path} is an invalid export location. Example --export-path /a/directory or ' \
                            f'--export-path s3://mybucket location'
            self.assertTrue(parsing_error_message == error_message)

    def test_export_invalid_s3_path_env_var_provided(self):
        for s3_path in self.invalid_s3_paths:
            os.environ['AWS_LABELER_EXPORT_PATH'] = s3_path
            parsing_error_message = get_parsing_error_message(get_arguments, MINIMUM_REQUIRED_ARGUMENTS)
            error_message = f'{s3_path} is an invalid export location. Example --export-path /a/directory or ' \
                            f'--export-path s3://mybucket location'
            self.assertTrue(parsing_error_message == error_message)
            del os.environ['AWS_LABELER_EXPORT_PATH']

    def test_export_metrics_only_argument_provided(self):
        arguments = ['-r', 'eu-west-1', '-o', 'ORG', '-e']
        args = get_arguments(arguments)
        self.assertFalse(args.export_all)

    def test_export_metrics_only_long_argument_provided(self):
        arguments = ['-r', 'eu-west-1', '-o', 'ORG', '--export-metrics-only']
        args = get_arguments(arguments)
        self.assertFalse(args.export_all)

    def test_export_valid_metrics_only_env_var_provided(self):
        for value in ['t', 'T', 'true', 'True', '1', 'TRUE']:
            os.environ['AWS_LABELER_EXPORT_ONLY_METRICS'] = value
            args = get_arguments(MINIMUM_REQUIRED_ARGUMENTS)
            self.assertFalse(args.export_all)
            del os.environ['AWS_LABELER_EXPORT_ONLY_METRICS']

    def test_export_invalid_metrics_only_env_var_provided(self):
        for value in ['TrUe', 'bob', 'garbage']:
            os.environ['AWS_LABELER_EXPORT_ONLY_METRICS'] = value
            args = get_arguments(MINIMUM_REQUIRED_ARGUMENTS)
            self.assertTrue(args.export_all)
            del os.environ['AWS_LABELER_EXPORT_ONLY_METRICS']

    def test_export_to_json_argument_not_provided(self):
        args = get_arguments(MINIMUM_REQUIRED_ARGUMENTS)
        self.assertFalse(args.to_json)

    def test_export_to_json_argument_provided(self):
        arguments = ['-r', 'eu-west-1', '-o', 'ORG', '-j']
        args = get_arguments(arguments)
        self.assertTrue(args.to_json)

    def test_export_to_json_long_argument_provided(self):
        arguments = ['-r', 'eu-west-1', '-o', 'ORG', '--to-json']
        args = get_arguments(arguments)
        self.assertTrue(args.to_json)

    def test_export_valid_to_json_env_var_provided(self):
        for value in ['t', 'T', 'true', 'True', '1', 'TRUE']:
            os.environ['AWS_LABELER_TO_JSON'] = value
            args = get_arguments(MINIMUM_REQUIRED_ARGUMENTS)
            self.assertTrue(args.to_json)
            del os.environ['AWS_LABELER_TO_JSON']

    def test_export_invalid_to_json_env_var_provided(self):
        for value in ['TrUe', 'bob', 'garbage']:
            os.environ['AWS_LABELER_TO_JSON'] = value
            args = get_arguments(MINIMUM_REQUIRED_ARGUMENTS)
            self.assertFalse(args.to_json)
            del os.environ['AWS_LABELER_TO_JSON']


class TestReportingArgs(unittest.TestCase):

    def test_valid_report_closed_findings_days_argument_provided(self):
        for days in [5, '6', '100', 3 * 5]:
            arguments = ['-r', 'eu-west-1', '-o', 'ORG', '-rd', str(days)]
            args = get_arguments(arguments)
            self.assertTrue(args.report_closed_findings_days == int(days))

    def test_valid_report_closed_findings_days_long_argument_provided(self):
        for days in [5, '6', '100', 3 * 5]:
            arguments = ['-r', 'eu-west-1', '-o', 'ORG', '--report-closed-findings-days', str(days)]
            args = get_arguments(arguments)
            self.assertTrue(args.report_closed_findings_days == int(days))

    def test_invalid_report_closed_findings_days_argument_provided(self):
        error_message = 'argument --report-closed-findings-days/-rd: {value} is an invalid positive int value'
        for value in ['a', -1, 'garbage']:
            arguments = ['-r', 'eu-west-1', '-o', 'ORG', '-rd', str(value)]
            parsing_error_message = get_parsing_error_message(get_arguments, arguments)
            self.assertTrue(parsing_error_message == error_message.format(value=value))

    def test_invalid_report_closed_findings_days_long_argument_provided(self):
        error_message = 'argument --report-closed-findings-days/-rd: {value} is an invalid positive int value'
        for value in ['a', -1, 'garbage']:
            arguments = ['-r', 'eu-west-1', '-o', 'ORG', '--report-closed-findings-days', str(value)]
            parsing_error_message = get_parsing_error_message(get_arguments, arguments)
            self.assertTrue(parsing_error_message == error_message.format(value=value))

    def test_valid_report_closed_findings_days_env_var_provided(self):
        for days in [5, '6', '100', 3 * 5]:
            os.environ['AWS_LABELER_REPORT_CLOSED_FINDINGS_DAYS'] = str(days)
            args = get_arguments(MINIMUM_REQUIRED_ARGUMENTS)
            self.assertTrue(args.report_closed_findings_days == int(days))
            del os.environ['AWS_LABELER_REPORT_CLOSED_FINDINGS_DAYS']

    def test_invalid_report_closed_findings_days_env_var_provided(self):
        error_message = 'argument --report-closed-findings-days/-rd: {value} is an invalid positive int value'
        for value in ['a', -1, 'garbage']:
            os.environ['AWS_LABELER_REPORT_CLOSED_FINDINGS_DAYS'] = str(value)
            parsing_error_message = get_parsing_error_message(get_arguments, MINIMUM_REQUIRED_ARGUMENTS)
            self.assertTrue(parsing_error_message == error_message.format(value=value))
            del os.environ['AWS_LABELER_REPORT_CLOSED_FINDINGS_DAYS']

    def test_report_suppressed_findings_argument_not_provided(self):
        args = get_arguments(MINIMUM_REQUIRED_ARGUMENTS)
        self.assertFalse(args.report_suppressed_findings)

    def test_report_suppressed_findings_argument_provided(self):
        arguments = ['-r', 'eu-west-1', '-o', 'ORG', '-rs']
        args = get_arguments(arguments)
        self.assertTrue(args.report_suppressed_findings)

    def test_report_suppressed_findings_long_argument_provided(self):
        arguments = ['-r', 'eu-west-1', '-o', 'ORG', '--report-suppressed-findings']
        args = get_arguments(arguments)
        self.assertTrue(args.report_suppressed_findings)

    def test_report_suppressed_findings_env_var_provided(self):
        for value in ['t', 'T', 'true', 'True', '1', 'TRUE']:
            os.environ['AWS_LABELER_REPORT_SUPPRESSED_FINDINGS'] = value
            args = get_arguments(MINIMUM_REQUIRED_ARGUMENTS)
            self.assertTrue(args.report_suppressed_findings)
            del os.environ['AWS_LABELER_REPORT_SUPPRESSED_FINDINGS']

    def test_report_suppressed_findings_invalid_env_var_provided(self):
        for value in ['TrUe', 'bob', 'garbage']:
            os.environ['AWS_LABELER_REPORT_SUPPRESSED_FINDINGS'] = value
            args = get_arguments(MINIMUM_REQUIRED_ARGUMENTS)
            self.assertFalse(args.report_suppressed_findings)
            del os.environ['AWS_LABELER_REPORT_SUPPRESSED_FINDINGS']


class TestThresholdsArgs(unittest.TestCase):

    def setUp(self) -> None:
        self.invalid_json_string = '"sddf'
        self.valid_json_string = '"{}"'
        self.invalid_account_json_message = 'argument --account-thresholds/-at: {value} is an invalid json string.'
        self.invalid_account_thresholds_message = 'argument --account-thresholds/-at: Provided configuration {value} ' \
                                                  'is an invalid accounts thresholds configuration.'
        self.valid_account_thresholds = json.dumps(ACCOUNT_THRESHOLDS)
        self.invalid_zone_json_message = 'argument --zone-thresholds/-zt: {value} is an invalid json string.'
        self.invalid_zone_thresholds_message = 'argument --zone-thresholds/-zt: Provided configuration {value} ' \
                                               'is an invalid zone thresholds configuration.'
        self.valid_zone_thresholds = json.dumps(ZONE_THRESHOLDS)

    def test_invalid_json_account_thresholds_argument_provided(self):
        arguments = MINIMUM_REQUIRED_ARGUMENTS + ['-at', self.invalid_json_string]
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        self.assertTrue(parsing_error_message == self.invalid_account_json_message.format(
            value=self.invalid_json_string))

    def test_invalid_json_account_thresholds_long_argument_provided(self):
        arguments = MINIMUM_REQUIRED_ARGUMENTS + ['--account-thresholds', self.invalid_json_string]
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        self.assertTrue(parsing_error_message == self.invalid_account_json_message.format(
            value=self.invalid_json_string))

    def test_valid_json_account_thresholds_argument_provided(self):
        arguments = MINIMUM_REQUIRED_ARGUMENTS + ['-at', self.valid_account_thresholds]
        args = get_arguments(arguments)
        self.assertTrue(args.account_thresholds == ACCOUNT_THRESHOLDS)

    def test_valid_json_account_thresholds_long_argument_provided(self):
        arguments = MINIMUM_REQUIRED_ARGUMENTS + ['--account-thresholds', self.valid_account_thresholds]
        args = get_arguments(arguments)
        self.assertTrue(args.account_thresholds == ACCOUNT_THRESHOLDS)

    def test_invalid_account_thresholds_argument_provided(self):
        arguments = MINIMUM_REQUIRED_ARGUMENTS + ['-at', self.valid_json_string]
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        self.assertTrue(parsing_error_message == self.invalid_account_thresholds_message.format(
            value=self.valid_json_string))

    def test_invalid_account_thresholds_long_argument_provided(self):
        arguments = MINIMUM_REQUIRED_ARGUMENTS + ['--account-thresholds', self.valid_json_string]
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        self.assertTrue(parsing_error_message == self.invalid_account_thresholds_message.format(
            value=self.valid_json_string))

    def test_invalid_json_account_thresholds_env_var_provided(self):
        os.environ['AWS_LABELER_ACCOUNT_THRESHOLDS'] = self.invalid_json_string
        parsing_error_message = get_parsing_error_message(get_arguments, MINIMUM_REQUIRED_ARGUMENTS)
        del os.environ['AWS_LABELER_ACCOUNT_THRESHOLDS']
        self.assertTrue(parsing_error_message == self.invalid_account_json_message.format(
            value=self.invalid_json_string))

    def test_valid_json_account_thresholds_env_var_provided(self):
        os.environ['AWS_LABELER_ACCOUNT_THRESHOLDS'] = self.valid_account_thresholds
        args = get_arguments(MINIMUM_REQUIRED_ARGUMENTS)
        del os.environ['AWS_LABELER_ACCOUNT_THRESHOLDS']
        self.assertTrue(args.account_thresholds == ACCOUNT_THRESHOLDS)

    def test_invalid_account_thresholds_env_var_provided(self):
        os.environ['AWS_LABELER_ACCOUNT_THRESHOLDS'] = self.valid_json_string
        parsing_error_message = get_parsing_error_message(get_arguments, MINIMUM_REQUIRED_ARGUMENTS)
        del os.environ['AWS_LABELER_ACCOUNT_THRESHOLDS']
        self.assertTrue(parsing_error_message == self.invalid_account_thresholds_message.format(
            value=self.valid_json_string))

    ####
    def test_invalid_json_zone_thresholds_argument_provided(self):
        arguments = MINIMUM_REQUIRED_ARGUMENTS + ['-zt', self.invalid_json_string]
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        self.assertTrue(parsing_error_message == self.invalid_zone_json_message.format(
            value=self.invalid_json_string))

    def test_invalid_json_zone_thresholds_long_argument_provided(self):
        arguments = MINIMUM_REQUIRED_ARGUMENTS + ['--zone-thresholds', self.invalid_json_string]
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        self.assertTrue(parsing_error_message == self.invalid_zone_json_message.format(
            value=self.invalid_json_string))

    def test_valid_json_zone_thresholds_argument_provided(self):
        arguments = MINIMUM_REQUIRED_ARGUMENTS + ['-zt', self.valid_zone_thresholds]
        args = get_arguments(arguments)
        self.assertTrue(args.zone_thresholds == ZONE_THRESHOLDS)

    def test_valid_json_zone_thresholds_long_argument_provided(self):
        arguments = MINIMUM_REQUIRED_ARGUMENTS + ['--zone-thresholds', self.valid_zone_thresholds]
        args = get_arguments(arguments)
        self.assertTrue(args.zone_thresholds == ZONE_THRESHOLDS)

    def test_invalid_zone_thresholds_argument_provided(self):
        arguments = MINIMUM_REQUIRED_ARGUMENTS + ['-zt', self.valid_json_string]
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        self.assertTrue(parsing_error_message == self.invalid_zone_thresholds_message.format(
            value=self.valid_json_string))

    def test_invalid_zone_thresholds_long_argument_provided(self):
        arguments = MINIMUM_REQUIRED_ARGUMENTS + ['--zone-thresholds', self.valid_json_string]
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        self.assertTrue(parsing_error_message == self.invalid_zone_thresholds_message.format(
            value=self.valid_json_string))

    def test_invalid_json_zone_thresholds_env_var_provided(self):
        os.environ['AWS_LABELER_ZONE_THRESHOLDS'] = self.invalid_json_string
        parsing_error_message = get_parsing_error_message(get_arguments, MINIMUM_REQUIRED_ARGUMENTS)
        del os.environ['AWS_LABELER_ZONE_THRESHOLDS']
        self.assertTrue(parsing_error_message == self.invalid_zone_json_message.format(
            value=self.invalid_json_string))

    def test_valid_json_zone_thresholds_env_var_provided(self):
        os.environ['AWS_LABELER_ZONE_THRESHOLDS'] = self.valid_zone_thresholds
        args = get_arguments(MINIMUM_REQUIRED_ARGUMENTS)
        del os.environ['AWS_LABELER_ZONE_THRESHOLDS']
        self.assertTrue(args.zone_thresholds == ZONE_THRESHOLDS)

    def test_invalid_zone_thresholds_env_var_provided(self):
        os.environ['AWS_LABELER_ZONE_THRESHOLDS'] = self.valid_json_string
        parsing_error_message = get_parsing_error_message(get_arguments, MINIMUM_REQUIRED_ARGUMENTS)
        del os.environ['AWS_LABELER_ZONE_THRESHOLDS']
        self.assertTrue(parsing_error_message == self.invalid_zone_thresholds_message.format(
            value=self.valid_json_string))


class TestSecurityHubQueryFilterArgs(unittest.TestCase):

    def setUp(self) -> None:
        self.invalid_json_string = '"sddf'
        self.valid_json_string = '"{}"'
        self.invalid_query_json_message = 'argument --security-hub-query-filter/-sf: {value} is an invalid json string.'

    def test_valid_json_query_filter_argument_provided(self):
        arguments = MINIMUM_REQUIRED_ARGUMENTS + ['-sf', self.valid_json_string]
        args = get_arguments(arguments)
        self.assertTrue(args.security_hub_query_filter == json.loads(self.valid_json_string))

    def test_valid_json_query_filter_long_argument_provided(self):
        arguments = MINIMUM_REQUIRED_ARGUMENTS + ['--security-hub-query-filter', self.valid_json_string]
        args = get_arguments(arguments)
        self.assertTrue(args.security_hub_query_filter == json.loads(self.valid_json_string))

    def test_invalid_json_query_filter_argument_provided(self):
        arguments = MINIMUM_REQUIRED_ARGUMENTS + ['-sf', self.invalid_json_string]
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        self.assertTrue(parsing_error_message == self.invalid_query_json_message.format(
            value=self.invalid_json_string))

    def test_invalid_json_query_filter_argument_provided(self):
        arguments = MINIMUM_REQUIRED_ARGUMENTS + ['--security-hub-query-filter', self.invalid_json_string]
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        self.assertTrue(parsing_error_message == self.invalid_query_json_message.format(
            value=self.invalid_json_string))

    def test_valid_json_query_filter_env_var_provided(self):
        os.environ['AWS_LABELER_SECURITY_HUB_QUERY_FILTER'] = self.valid_json_string
        args = get_arguments(MINIMUM_REQUIRED_ARGUMENTS)
        del os.environ['AWS_LABELER_SECURITY_HUB_QUERY_FILTER']
        self.assertTrue(args.security_hub_query_filter == json.loads(self.valid_json_string))

    def test_invalid_zone_thresholds_env_var_provided(self):
        os.environ['AWS_LABELER_SECURITY_HUB_QUERY_FILTER'] = self.invalid_json_string
        parsing_error_message = get_parsing_error_message(get_arguments, MINIMUM_REQUIRED_ARGUMENTS)
        del os.environ['AWS_LABELER_SECURITY_HUB_QUERY_FILTER']
        self.assertTrue(parsing_error_message == self.invalid_query_json_message.format(
            value=self.invalid_json_string))


class TestValidatingFile(unittest.TestCase):

    def setUp(self):
        self.non_existent_file_message = ('argument --validate-metadata-file/-vm: Local file path "{filepath}" '
                                          'provided, does not exist.')
        self.invalid_json_file_message = 'Local file "{filepath}" provided is not a valid json file!'

    def test_non_existent_local_file_provided_as_argument(self):
        not_existent_file = 'bobs_file'
        parsing_error_message = get_parsing_error_message(get_arguments, ['-vm', not_existent_file])
        self.assertTrue(parsing_error_message == self.non_existent_file_message.format(filepath=not_existent_file))

    def test_non_existent_local_file_provided_as_long_argument(self):
        not_existent_file = 'bobs_file'
        parsing_error_message = get_parsing_error_message(get_arguments, ['--validate-metadata-file',
                                                                          not_existent_file])
        self.assertTrue(parsing_error_message == self.non_existent_file_message.format(filepath=not_existent_file))

    def test_invalid_json_file_provided_as_argument(self):
        invalid_json_file = str(Path('tests/fixtures/garbage.json').resolve())
        parsing_error_message = get_parsing_error_message(get_arguments, ['-vm', invalid_json_file])
        self.assertTrue(parsing_error_message == self.invalid_json_file_message.format(filepath=invalid_json_file))

    def test_invalid_json_file_provided_as_long_argument(self):
        invalid_json_file = str(Path('tests/fixtures/garbage.json').resolve())
        parsing_error_message = get_parsing_error_message(get_arguments, ['--validate-metadata-file',
                                                                          invalid_json_file])
        self.invalid_json_file_message.format(filepath=invalid_json_file)
        self.assertTrue(parsing_error_message == self.invalid_json_file_message.format(filepath=invalid_json_file))

    def test_invalid_hashed_json_local_file_provided_as_argument(self):
        invalid_hashed_file = 'tests/fixtures/metadata_invalid.json'
        parsing_error_message = get_parsing_error_message(get_arguments, ['-vm', invalid_hashed_file])
        self.assertTrue('does not match the calculated one' in parsing_error_message)

    def test_invalid_hashed_json_local_file_provided_as_long_argument(self):
        invalid_hashed_file = 'tests/fixtures/metadata_invalid.json'
        parsing_error_message = get_parsing_error_message(get_arguments, ['--validate-metadata-file',
                                                                          invalid_hashed_file])
        self.assertTrue('does not match the calculated one' in parsing_error_message)

    def test_valid_hashed_json_local_file_provided_as_argument(self):
        valid_hashed_local_file = 'tests/fixtures/metadata_valid.json'
        with self.assertRaises(SystemExit) as cm:
            get_arguments(['-vm', valid_hashed_local_file])
        self.assertEqual(cm.exception.code, 0)

    def test_valid_hashed_json_local_file_provided_as_long_argument(self):
        valid_hashed_local_file = 'tests/fixtures/metadata_valid.json'
        with self.assertRaises(SystemExit) as cm:
            get_arguments(['--validate-metadata-file', valid_hashed_local_file])
        self.assertEqual(cm.exception.code, 0)


class TestVersion(unittest.TestCase):

    def test_version_provided_as_argument(self):
        with self.assertRaises(SystemExit) as cm:
            get_arguments(['-v'])
        self.assertEqual(cm.exception.code, 0)

    def test_version_provided_as_long_argument(self):
        with self.assertRaises(SystemExit) as cm:
            get_arguments(['--version'])
        self.assertEqual(cm.exception.code, 0)
