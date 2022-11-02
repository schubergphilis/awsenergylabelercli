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
import os
import sys
import unittest

from awsenergylabelercli import get_arguments, get_parser
from awsenergylabelercli.validators import (character_delimited_list_variable,
                                            environment_variable_boolean,
                                            positive_integer,
                                            json_string,
                                            aws_account_id)
from awsenergylabelerlib import SECURITY_HUB_ACTIVE_REGIONS, DEFAULT_SECURITY_HUB_FRAMEWORKS, SecurityHub


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

    def test_valid_region_argument_provided(self):
        valid_region = 'eu-west-1'
        args = get_arguments(['-r', valid_region, '-z', 'DUMMY_ZONE_NAME'])
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

        This is where you can setup things that you use throughout the tests. This method is called before every test.
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

    def test_valid_organization_name_env_var_provided(self):
        valid_org_name = 'TEST_ORG'
        os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME'] = valid_org_name
        args = get_arguments(['-r', 'eu-west-1', '-o', valid_org_name])
        del os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME']
        self.assertTrue(args.organizations_zone_name == valid_org_name)

    def test_mutually_exclusive_with_audit_zone_both_as_arguments(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '-o', 'ORG_NAME',
                                                                          '-z', 'ZONE_NAME'])
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_single_account_both_as_arguments(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1',
                                                                          '-o', 'ORG_NAME',
                                                                          '-s', '123456789012'])
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_audit_zone_organization_as_env_var(self):
        valid_org_name = 'VALID_ORG'
        os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME'] = valid_org_name
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1', '-z', 'ZONE_NAME'])
        del os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME']
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_single_account_organization_as_env_var(self):
        valid_org_name = 'VALID_ORG'
        os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME'] = valid_org_name
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1', '-s', '123456789012'])
        del os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME']
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_audit_zone_as_env_var(self):
        os.environ['AWS_LABELER_AUDIT_ZONE_NAME'] = 'ZONE_NAME'
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1', '-o', 'ORG_NAME'])
        del os.environ['AWS_LABELER_AUDIT_ZONE_NAME']
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_single_account_as_env_var(self):
        os.environ['AWS_LABELER_SINGLE_ACCOUNT_ID'] = '123456789012'
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1', '-o', 'ORG_NAME'])
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

    def test_mutually_exclusive_with_organizations_as_env_var(self):
        valid_org_name = 'VALID_ORG'
        os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME'] = valid_org_name
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1', '-z', 'AUDIT_ZONE'])
        del os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME']
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_single_account_as_env_var(self):
        os.environ['AWS_LABELER_SINGLE_ACCOUNT_ID'] = '123456789012'
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1', '-z', 'AUDIT_ZONE'])
        del os.environ['AWS_LABELER_SINGLE_ACCOUNT_ID']
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)


class TestSingleAccount(TestZone):

    def test_missing_single_account(self):
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1'])
        self.assertTrue(parsing_error_message == self.missing_arguments_message)

    def test_valid_single_account_argument_provided(self):
        valid_single_account = '123456789012'
        args = get_arguments(['-r', 'eu-west-1', '-s', valid_single_account])
        self.assertTrue(args.single_account_id == valid_single_account)

    def test_valid_single_account_id_env_var_provided(self):
        valid_single_account = '123456789012'
        os.environ['AWS_LABELER_SINGLE_ACCOUNT_ID'] = valid_single_account
        args = get_arguments(['-r', 'eu-west-1'])
        del os.environ['AWS_LABELER_SINGLE_ACCOUNT_ID']
        self.assertTrue(args.single_account_id == valid_single_account)

    def test_mutually_exclusive_with_organizations_as_env_var(self):
        valid_org_name = 'VALID_ORG'
        os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME'] = valid_org_name
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1', '-s', '123456789012'])
        del os.environ['AWS_LABELER_ORGANIZATIONS_ZONE_NAME']
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_mutually_exclusive_with_audit_zone_as_env_var(self):
        os.environ['AWS_LABELER_AUDIT_ZONE_NAME'] = 'ZONE_NAME'
        parsing_error_message = get_parsing_error_message(get_arguments, ['-r', 'eu-west-1', '-s', '123456789012'])
        del os.environ['AWS_LABELER_AUDIT_ZONE_NAME']
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)


class TestFrameworks(unittest.TestCase):

    def setUp(self) -> None:
        self.error_message = ('{provided_frameworks} are not valid supported security hub frameworks. Currently '
                              'supported are {frameworks}')

    def test_empty_frameworks(self):
        args = get_arguments(['-r', 'eu-west-1', '-o', 'ORG', '-f', ''])
        self.assertTrue(args.frameworks == [])

    def test_default_frameworks(self):
        args = get_arguments(['-r', 'eu-west-1', '-o', 'ORG'])
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

    def test_invalid_frameworks_as_env_var(self):
        os.environ['AWS_LABELER_FRAMEWORKS'] = 'aws-foundational-security-best-practices,bob'
        arguments = ['-r', 'eu-west-1', '-o', 'ORG']
        parser = get_parser()
        error_frameworks = parser.parse_args(arguments).frameworks
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        del os.environ['AWS_LABELER_FRAMEWORKS']
        error_message = self.error_message.format(provided_frameworks=error_frameworks,
                                                  frameworks=SecurityHub.frameworks)
        self.assertTrue(parsing_error_message == error_message)


class TestAccountIds(unittest.TestCase):

    def setUp(self) -> None:
        self.mutually_exclusive_arguments_message = ('argument --allowed-account-ids/-a: not allowed with argument '
                                                     '--denied-account-ids/-d')

    def test_mutually_exclusive_account_id_arguments(self):
        arguments = ['-r', 'eu-west-1', '-o', 'ORG', '-a', '123456789012', '-d', '123456789012']
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        self.assertTrue(parsing_error_message == self.mutually_exclusive_arguments_message)

    def test_allowed_account_ids_valid_as_argument(self):
        valid_account_ids = ['123456789012', '234567890123']
        args = get_arguments(['-r', 'eu-west-1', '-o', 'ORG_NAME', '-a', ','.join(valid_account_ids)])
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

    def test_denied_account_ids_valid_as_env_var(self):
        valid_account_ids = ['123456789012', '234567890123']
        os.environ['AWS_LABELER_DENIED_ACCOUNT_IDS'] = ','.join(valid_account_ids)
        args = get_arguments(['-r', 'eu-west-1', '-o', 'ORG_NAME'])
        del os.environ['AWS_LABELER_DENIED_ACCOUNT_IDS']
        self.assertTrue(args.denied_account_ids == valid_account_ids)

    def test_denied_account_ids_invalid_as_argument(self):
        invalid_account_ids = ['a123456789012', '2345678s90123']
        arguments = ['-r', 'eu-west-1', '-o', 'ORG_NAME', '-a', ','.join(invalid_account_ids)]
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

    def test_allowed_regions_valid_as_argument(self):
        args = get_arguments(['-r', 'eu-west-1', '-o', 'ORG_NAME', '-ar', ','.join(self.valid_regions)])
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

    def test_denied_regions_invalid_as_env_var(self):
        os.environ['AWS_LABELER_DENIED_REGIONS'] = ','.join(self.invalid_regions)
        arguments = ['-r', 'eu-west-1', '-o', 'ORG_NAME']
        parsing_error_message = get_parsing_error_message(get_arguments, arguments)
        del os.environ['AWS_LABELER_DENIED_REGIONS']
        error_message = f'{self.invalid_regions} contains invalid regions.'
        self.assertTrue(parsing_error_message == error_message)
