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
import json
import logging
import os
import re
from argparse import ArgumentTypeError
from pathlib import Path

from schema import SchemaUnexpectedTypeError, SchemaError
from awsenergylabelerlib import (is_valid_account_id,
                                 is_valid_region,
                                 SECURITY_HUB_ACTIVE_REGIONS)
from awsenergylabelerlib.schemas import account_thresholds_schema, zone_thresholds_schema

from .awsenergylabelercliexceptions import MutuallyExclusiveArguments, MissingRequiredArguments

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
    result = [entry for entry in re.split(delimiting_characters, str(value)) if entry]
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


def positive_integer(value):
    """Casts an argument to an int and validates that it is a positive number.

    Args:
        value: The value to cast.

    Returns:
        The positive integer.

    Raises:
        ArgumentTypeError: If the argument cannot be cast or if it is a negative number.

    """
    if value is None:
        return value
    try:
        num_value = int(value)
    except ValueError:
        num_value = -1
    if num_value <= 0:
        raise ArgumentTypeError(f'{value} is an invalid positive int value')
    return num_value


def get_mutually_exclusive_args(*args, required=False):
    """Test if multiple mutually exclusive arguments are provided."""
    set_arguments = [arg for arg in args if arg]
    if len(set_arguments) > 1:
        raise MutuallyExclusiveArguments(*set_arguments)
    if required and not any(set_arguments):
        raise MissingRequiredArguments()
    return args


def default_environment_variable(variable_name):
    """Closure to pass the variable name to the inline custom Action.

    Args:
        variable_name: The variable to look up as environment variable.

    Returns:
        The Action object.

    """

    class DefaultEnvVar(argparse.Action):  # pylint: disable=too-few-public-methods
        """Default Environment Variable."""

        def __init__(self, *args, **kwargs):
            if variable_name in os.environ:
                kwargs['default'] = os.environ[variable_name]
            if kwargs.get('required') and kwargs.get('default'):
                kwargs['required'] = False
            super(DefaultEnvVar, self).__init__(*args, **kwargs)

        def __call__(self, parser, namespace, values, option_string=None):
            setattr(namespace, self.dest, values)

    return DefaultEnvVar


def json_string(value):
    """Validates that the provided argument is a valid json string.

    Args:
        value: The string to load as json

    Returns:
        The json object on success

    Raises:
        ArgumentTypeError on error.

    """
    if value is None:
        return None
    try:
        json_value = json.loads(value)
    except ValueError:
        raise ArgumentTypeError(f'{value} is an invalid json string.') from None
    return json_value


def account_thresholds_config(value):
    """Validates that the provided string value is an account thresholds configuration.

    Args:
        value: The value to  validate for an account thresholds configuration.

    Returns:
        A valid account configuration.

    """
    config = json_string(value)
    try:
        config = account_thresholds_schema.validate(config)
    except (SchemaUnexpectedTypeError, SchemaError):
        raise ArgumentTypeError(
            f'Provided configuration {value} is an invalid accounts thresholds configuration.') from None
    return config


def zone_thresholds_config(value):
    """Validates that the provided string value is a zone thresholds configuration.

    Args:
        value: The value to  validate for a zone thresholds configuration.

    Returns:
        A valid zone configuration.

    """
    config = json_string(value)
    try:
        config = zone_thresholds_schema.validate(config)
    except (SchemaUnexpectedTypeError, SchemaError):
        raise ArgumentTypeError(
            f'Provided configuration {value} is an invalid zone thresholds configuration.') from None
    return config


class OverridingArgument(argparse.Action):  # pylint: disable=too-few-public-methods
    """Argument that if set will disable all other arguments that are set as required."""

    def __call__(self, parser, namespace, values, option_string=None):
        # If we get here, it means that the argument is set so any other argument that has been configured as required
        # will have it's required attribute disabled due to this overriding argument being called.
        for argument in parser._actions:  # noqa
            if argument.required:
                # this will not log as the logger is set up up after the parsing of arguments. Message is left as
                # documentation and can be turned into a print statement for debugging.
                LOGGER.info(f'Argument {argument.dest} is required, overriding that to not required due to argument '
                            f'{self.dest} set as overriding argument which will disable all other required arguments.')
                argument.required = False
        # if we get here there has been an argument provided so to support flag arguments if no actual value has been
        # provided we set the argument to True. Assumption is that the argument has been configured with nargs=0.
        values = True if not values else values
        setattr(namespace, self.dest, values)


def valid_local_file(local_path):
    """Validates an argparse argument to be an existing local file.

    Args:
        local_path: The path provided as an argument.

    Returns:
        The local path if the file exists.

    Raises:
        ArgumentTypeError: If the file does not exist.

    """
    path_file = Path(local_path)
    if not path_file.exists():
        raise ArgumentTypeError(f'Local file path "{local_path}" provided, does not exist.')
    return path_file.resolve()
