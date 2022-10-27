#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: validators.py
#
# Copyright 2022 Theodoor Scholte, Costas Tyfoxylos, Jenda Brands
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
Main code for validators.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import argparse
import logging
import re
from argparse import ArgumentTypeError

from awsenergylabelerlib import (is_valid_account_id,
                                 is_valid_region,
                                 DestinationPath,
                                 SECURITY_HUB_ACTIVE_REGIONS,
                                 SecurityHub,
                                 InvalidFrameworks,
                                 validate_account_ids,
                                 validate_regions,
                                 InvalidAccountListProvided,
                                 InvalidRegionListProvided)

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''08-04-2022'''
__copyright__ = '''Copyright 2022, Costas Tyfoxylos'''
__credits__ = ["Theodoor Scholte", "Costas Tyfoxylos", "Jenda Brands"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is the main prefix used for logging
LOGGER_BASENAME = '''validators'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


class ValidatePath(argparse.Action):  # pylint: disable=too-few-public-methods
    """Validates a given path."""

    def __call__(self, parser, namespace, values, option_string=None):
        destination = DestinationPath(values)
        if not destination.is_valid():
            raise parser.error(f'{values} is an invalid export location. Example --export-path '
                               f'/a/directory or --export-path s3://mybucket location')
        setattr(namespace, self.dest, values)


class ValidateFrameworks(argparse.Action):  # pylint: disable=too-few-public-methods
    """Validates that the values provided are valid and supported aws security hub frameworks."""

    def __call__(self, parser, namespace, values, option_string=None):
        try:
            SecurityHub.validate_frameworks(values)
        except InvalidFrameworks:
            raise parser.error(f'{values} are not valid supported security hub frameworks. Currently '
                               f'supported are {SecurityHub.frameworks}') from None
        setattr(namespace, self.dest, values)


class ValidateAccountIds(argparse.Action):  # pylint: disable=too-few-public-methods
    """Validates that the values provided are valid and supported aws security hub frameworks."""

    def __call__(self, parser, namespace, values, option_string=None):
        try:
            validate_account_ids(values)
        except InvalidAccountListProvided:
            raise parser.error(f'{values} contains invalid accounts IDS') from None
        setattr(namespace, self.dest, values)


class ValidateRegions(argparse.Action):  # pylint: disable=too-few-public-methods
    """Validates that the values provided are valid and supported aws security hub frameworks."""

    def __call__(self, parser, namespace, values, option_string=None):
        try:
            validate_regions(values)
        except InvalidRegionListProvided:
            raise parser.error(f'Invalid regions in provided arguments: {values}') from None
        setattr(namespace, self.dest, values)


def aws_account_id(account_id):
    """Setting a type for an account id argument."""
    if not is_valid_account_id(account_id):
        raise ArgumentTypeError(f'Account id {account_id} provided does not seem to be valid.')
    return account_id


def security_hub_region(region):
    """Setting a type for a security hub region."""
    if not is_valid_region(region):
        raise ArgumentTypeError(f'Region {region} provided does not seem to be valid, valid regions are '
                                f'{SECURITY_HUB_ACTIVE_REGIONS}.')
    return region


def character_delimited_list_variable(value):
    """Support for environment variables with characters delimiting a list of value."""
    delimiting_characters = '[,|\\s]'
    result = [entry for entry in re.split(delimiting_characters, value) if entry]
    if len(result) == 1:
        return result[0]
    return result


def environment_variable_boolean(value):
    """Parses an environment variable as a boolean.

    Args:
        value: The value of the environment variable.

    Returns:
        True if environment variable is one of the supported values, False otherwise.

    """
    if value in [True, 't', 'T', 'true', 'True', 1, '1', 'TRUE']:
        return True
    return False
