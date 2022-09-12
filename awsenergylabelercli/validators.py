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
from argparse import ArgumentTypeError

from awsenergylabelerlib import (is_valid_account_id,
                                 is_valid_region,
                                 DestinationPath,
                                 SECURITY_HUB_ACTIVE_REGIONS)

from .awsenergylabelercliexceptions import (MutuallyExclusiveArguments,
                                            MissingRequiredArguments)

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

    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError("nargs not allowed")
        super(ValidatePath, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        destination = DestinationPath(values)
        if not destination.is_valid():
            raise argparse.ArgumentTypeError(f'{values} is an invalid export location. '
                                             f'Example --export-path /a/directory or '
                                             f'--export-path s3://mybucket location')
        setattr(namespace, self.dest, values)


def aws_account_id(account_id):
    """Setting a type for an account id argument."""
    if not is_valid_account_id(account_id):
        raise ArgumentTypeError(f'Account id {account_id} provided does not seem to be valid.')
    return account_id


def security_hub_region(region):
    """Setting a type for an security hub region."""
    if not is_valid_region(region):
        raise ArgumentTypeError(f'Region {region} provided does not seem to be valid, valid regions are '
                                f'{SECURITY_HUB_ACTIVE_REGIONS}.')
    return region


def get_mutually_exclusive_args(arg1, arg2, required=False):
    """Test if multiple mutually exclusive arguments are provided."""
    if arg1 and arg2:
        raise MutuallyExclusiveArguments(arg1, arg2)
    if required and not (arg1 or arg2):
        raise MissingRequiredArguments()
    return arg1, arg2
