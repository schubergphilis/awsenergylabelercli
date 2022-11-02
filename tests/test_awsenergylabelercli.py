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

import contextlib
import io
import os
import sys
import unittest

from awsenergylabelercli import get_arguments
from awsenergylabelerlib import SECURITY_HUB_ACTIVE_REGIONS


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


class TestRegion(unittest.TestCase):
    def test_missing_region(self):
        self.assertTrue(get_parsing_error_message(get_arguments, []) == 'the following arguments are required: --region/-r')

    def test_invalid_region(self):
        invalid_region = 'bob'
        error_message = f'argument --region/-r: Region {invalid_region} provided does not seem to be valid, valid ' \
                        f'regions are {SECURITY_HUB_ACTIVE_REGIONS}.'
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
        error_message = f'argument --region/-r: Region {invalid_region} provided does not seem to be valid, valid ' \
                        f'regions are {SECURITY_HUB_ACTIVE_REGIONS}.'
        parsing_error_message = get_parsing_error_message(get_arguments, ['-z', 'DUMMY_ZONE_NAME'])
        del os.environ['AWS_LABELER_REGION']
        self.assertTrue(parsing_error_message == error_message)


class TestOrganization(unittest.TestCase):
    def setUp(self):
        """
        Test set up

        This is where you can setup things that you use throughout the tests. This method is called before every test.
        """
        self.missing_arguments_message = ('one of the arguments --organizations-zone-name/-o '
                                          '--audit-zone-name/-z --single-account-id/-s is required')
        self.mutually_exclusive_arguments_message = ('arguments --organizations-zone-name/-o --audit-zone-name/-z '
                                                     '--single-account-id/-s are mutually exclusive')

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


class TestAuditZone(unittest.TestCase):

    def setUp(self):
        """
        Test set up

        This is where you can setup things that you use throughout the tests. This method is called before every test.
        """
        self.missing_arguments_message = ('one of the arguments --organizations-zone-name/-o '
                                          '--audit-zone-name/-z --single-account-id/-s is required')
        self.mutually_exclusive_arguments_message = ('arguments --organizations-zone-name/-o --audit-zone-name/-z '
                                                     '--single-account-id/-s are mutually exclusive')
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


class TestSingleAccount(unittest.TestCase):

    def setUp(self):
        """
        Test set up

        This is where you can setup things that you use throughout the tests. This method is called before every test.
        """
        self.missing_arguments_message = ('one of the arguments --organizations-zone-name/-o '
                                          '--audit-zone-name/-z --single-account-id/-s is required')
        self.mutually_exclusive_arguments_message = ('arguments --organizations-zone-name/-o --audit-zone-name/-z '
                                                     '--single-account-id/-s are mutually exclusive')
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
