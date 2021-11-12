#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: awsenergylabelercli.py
#
# Copyright 2021 Theodoor Scholte
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
Main code for awsenergylabelercli.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import argparse
import json
import logging
import logging.config
import sys

import coloredlogs

from awsenergylabelerlib import EnergyLabeler

from awsenergylabelercli.helpers import DestinationPath, DataExporter

__author__ = '''Theodoor Scholte <tscholte@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''11-11-2021'''
__copyright__ = '''Copyright 2021, Theodoor Scholte'''
__credits__ = ["Theodoor Scholte"]
__license__ = '''MIT'''
__maintainer__ = '''Theodoor Scholte'''
__email__ = '''<tscholte@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is the main prefix used for logging
LOGGER_BASENAME = '''awsenergylabelercli'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


class ValidatePath(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError("nargs not allowed")
        super(ValidatePath, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        destination = DestinationPath(values)
        if not destination.is_valid():
            raise argparse.ArgumentTypeError(f'{values} is an invalid export location. '
                                             f'Example --export /a/directory or --export s3://mybucket/ location')
        setattr(namespace, self.dest, values)


def get_arguments():
    """
    Gets us the cli arguments.

    Returns the args as parsed from the argsparser.
    """
    # https://docs.python.org/3/library/argparse.html
    parser = argparse.ArgumentParser(description='''A cli to label accounts and landing zones with energy labels based
    on Security Hub finding.''')
    parser.add_argument('--log-config',
                        '-l',
                        action='store',
                        dest='logger_config',
                        help='The location of the logging config json file',
                        default='')
    parser.add_argument('--log-level',
                        '-L',
                        help='Provide the log level. Defaults to info.',
                        dest='log_level',
                        action='store',
                        default='info',
                        choices=['debug',
                                 'info',
                                 'warning',
                                 'error',
                                 'critical'])
    parser.add_argument('--landingzone-name',
                        '-n',
                        type=str,
                        required=True,
                        help='The name of the Landing Zone.')
    parser.add_argument('--region',
                        default='eu-west-1',
                        type=str,
                        required=False,
                        help='The AWS region, default is eu-west-1')
    parser.add_argument('--frameworks',
                        default='aws-foundational-security-best-practices',
                        nargs='*',
                        help='The list of applicable frameworks: [aws-foundational-security-best-practices, cis], '
                             'default=aws-foundational-security-best-practices')
    account_list = parser.add_mutually_exclusive_group()
    account_list.add_argument('--allow-list',
                              nargs='*',
                              default=None,
                              required=False,
                              help='A list of AWS Account IDs for which an energy label will be produced.')
    account_list.add_argument('--deny-list',
                              nargs='*',
                              default=None,
                              required=False,
                              help='A list of AWS Account IDs that will be excluded from producing the energy label.')
    parser.add_argument('--export',
                        default='',
                        type=ValidatePath,
                        required=False,
                        help='Exports a snapshot of the reporting data in '
                             'JSON formatted files to the specified directory or S3 location.')
    try:
        args = parser.parse_args()
    except argparse.ArgumentTypeError:
        print('Invalid arguments provided, cannot continue.')
        raise SystemExit(1)
    return args


def setup_logging(level, config_file=None):
    """
    Sets up the logging.

    Needs the args to get the log level supplied

    Args:
        level: At which level do we log
        config_file: Configuration to use

    """
    # This will configure the logging, if the user has set a config file.
    # If there's no config file, logging will default to stdout.
    if config_file:
        # Get the config for the logger. Of course this needs exception
        # catching in case the file is not there and everything. Proper IO
        # handling is not shown here.
        try:
            with open(config_file) as conf_file:
                configuration = json.loads(conf_file.read())
                # Configure the logger
                logging.config.dictConfig(configuration)
        except ValueError:
            print(f'File "{config_file}" is not valid json, cannot continue.')
            raise SystemExit(1)
    else:
        coloredlogs.install(level=level.upper())


def main():
    """
    Main method.

    This method holds what you want to execute when
    the script is run on command line.
    """
    args = get_arguments()
    setup_logging(args.log_level, args.logger_config)

    LOGGER.debug(f'{sys.argv[0]} has started with arguments: {args}')
    labeler = EnergyLabeler(args.landingzone_name,
                            args.region,
                            args.frameworks,
                            allow_list=args.allow_list,
                            deny_list=args.deny_list)
    if args.export:
        exporter = DataExporter(labeler)
        exporter.export(args.export)
    print(f'Landing Zone: {args.landingzone_name}')
    print(f'Landing Zone Security Score: {labeler.landing_zone_energy_label}')
    print(f'Labeled Accounts Security Score: {labeler.labeled_accounts_energy_label}')
    raise SystemExit(0)


if __name__ == '__main__':
    main()
