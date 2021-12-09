#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: awsenergylabelercli.py
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
Main code for awsenergylabelercli.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import argparse
import json
import logging
import logging.config
import os
import os.path
import tempfile
from urllib.parse import urljoin, urlparse

import boto3
import coloredlogs
from terminaltables import AsciiTable
from art import text2art
from awsenergylabelerlib import (EnergyLabeler,
                                 NoRegion,
                                 NoAccess,
                                 InvalidOrNoCredentials,
                                 InvalidAccountListProvided,
                                 InvalidRegionListProvided,
                                 InvalidFrameworks)
from yaspin import yaspin

__author__ = '''Theodoor Scholte <tscholte@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''11-11-2021'''
__copyright__ = '''Copyright 2021, Theodoor Scholte'''
__credits__ = ["Theodoor Scholte", "Costas Tyfoxylos", "Jenda Brands"]
__license__ = '''MIT'''
__maintainer__ = '''Theodoor Scholte'''
__email__ = '''<tscholte@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is the main prefix used for logging
LOGGER_BASENAME = '''awsenergylabelercli'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())

EXPORT_TYPES = {
    'energy_label': 'energy_label',
    'findings': 'findings',
    'labeled_accounts': 'labeled_accounts'
}


class InvalidPath(Exception):
    """The path provided is not valid."""


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
                                             f'Example --export /a/directory or --export s3://mybucket location')
        setattr(namespace, self.dest, values)


class DestinationPath:
    """Models a destination path and identifies if it is valid and it's type."""

    def __init__(self, location):
        self.location = location
        self._parsed_url = urlparse(location)
        self._s3_conditions = [self._parsed_url.scheme == "s3", len(self._parsed_url.netloc) >= 1]
        self._local_conditions = [self._parsed_url.scheme == "",
                                  self._parsed_url.netloc == "",
                                  len(self._parsed_url.path) >= 1]

    def is_valid(self):
        """Is the path valid."""
        return all(self._s3_conditions) or all(self._local_conditions)

    @property
    def type(self):
        """The type of the path."""
        if all(self._s3_conditions):
            return 's3'
        if all(self._local_conditions):
            return 'local'
        raise InvalidPath(self.location)


class DataFileFactory:  # pylint: disable=too-few-public-methods
    """Data export factory to handle the different data types returned."""

    def __new__(cls, export_type, labeler):
        if export_type == EXPORT_TYPES.get('energy_label'):
            obj = EnergyLabelingData('energylabel-of-landingzone.json', labeler)
        elif export_type == EXPORT_TYPES.get('findings'):
            obj = SecurityHubFindingsData('securityhub-findings.json', labeler)
        elif export_type == EXPORT_TYPES.get('labeled_accounts'):
            obj = LabeledAccountsData('labeled-accounts.json', labeler)
        else:
            LOGGER.error('Unknown data type %s', export_type)
            return None
        return obj


class EnergyLabelingData:  # pylint: disable=too-few-public-methods
    """Models the data for energy labeling to export."""

    def __init__(self, filename, labeler):
        self.filename = filename
        self._labeler = labeler

    @property
    def json(self):
        """Data to json."""
        return json.dumps([{'Landing Zone Name': self._labeler.landing_zone_name,
                            'Landing Zone Energy Label': self._labeler.landing_zone_energy_label}],
                          indent=2, default=str)


class SecurityHubFindingsData:  # pylint: disable=too-few-public-methods
    """Models the data for energy labeling to export."""

    def __init__(self, filename, labeler):
        self.filename = filename
        self._labeler = labeler

    @property
    def json(self):
        """Data to json."""
        return json.dumps(self._labeler.security_hub_findings_data, indent=2, default=str)


class LabeledAccountsData:  # pylint: disable=too-few-public-methods
    """Models the data for energy labeling to export."""

    def __init__(self, filename, labeler):
        self.filename = filename
        self._labeler = labeler

    @property
    def json(self):
        """Data to json."""
        return json.dumps([{'Account ID': account.id,
                            'Account Name': account.name,
                            'Number of critical and high findings': account.number_of_critical_high_findings,
                            'Number of medium findings': account.number_of_medium_findings,
                            'Number of low findings': account.number_of_low_findings,
                            'Number of maximum days open': account.max_days_open,
                            'Energy Label': account.energy_label}
                           for account in self._labeler.labeled_accounts], indent=2, default=str)


class DataExporter:  # pylint: disable=too-few-public-methods
    """Export AWS security data."""

    def __init__(self, energy_labeler):
        self.energy_labeler = energy_labeler
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')

    def export(self, path):
        """Exports the data to the provided path."""
        destination = DestinationPath(path)
        if not destination.is_valid():
            raise InvalidPath(path)
        for export_type in EXPORT_TYPES.values():
            data_file = DataFileFactory(export_type, self.energy_labeler)
            if destination.type == 's3':
                self._export_to_s3(path, data_file.filename, data_file.json)  # pylint: disable=no-member
            else:
                self._export_to_fs(path, data_file.filename, data_file.json)  # pylint: disable=no-member

    def _export_to_fs(self, directory, filename, data):
        """Exports as json to local filesystem."""
        if not os.path.exists(directory):
            os.makedirs(directory)
        filepath = os.path.join(directory, filename)
        with open(filepath, 'w') as jsonfile:
            jsonfile.write(data)
        self._logger.info(f'File {filename} copied to {directory}')

    def _export_to_s3(self, s3_url, filename, data):
        """Exports as json to S3 object storage."""
        s3 = boto3.client('s3')  # pylint: disable=invalid-name
        parsed_url = urlparse(s3_url)
        bucket_name = parsed_url.netloc
        dst_path = parsed_url.path
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(data.encode('utf-8'))
            temp_file.flush()
            dst_filename = urljoin(dst_path, filename)
            s3.upload_file(temp_file.name, bucket_name, dst_filename)
            temp_file.close()
        self._logger.info(f'File {filename} copied to {s3_url}')


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
    parser.add_argument('--landing-zone-name',
                        '-n',
                        type=str,
                        required=True,
                        help='The name of the Landing Zone.')
    parser.add_argument('--region',
                        '-r',
                        default=None,
                        type=str,
                        required=False,
                        help='The AWS region, default is None')
    parser.add_argument('--frameworks',
                        '-f',
                        default='aws-foundational-security-best-practices',
                        nargs='*',
                        help='The list of applicable frameworks: \
                                [aws-foundational-security-best-practices, cis, pci-dss], '
                             'default=aws-foundational-security-best-practices')
    account_list = parser.add_mutually_exclusive_group()
    account_list.add_argument('--allow-list',
                              '-al',
                              nargs='*',
                              default=None,
                              required=False,
                              help='A list of AWS Account IDs for which an energy label will be produced.')
    account_list.add_argument('--deny-list',
                              '-dl',
                              nargs='*',
                              default=None,
                              required=False,
                              help='A list of AWS Account IDs that will be excluded from producing the energy label.')
    region_list = parser.add_mutually_exclusive_group()
    region_list.add_argument('--allowed-regions',
                             '-ar',
                             nargs='*',
                             default=None,
                             required=False,
                             help='A list of AWS regions included in producing the energy label.')
    region_list.add_argument('--denied-regions',
                             '-dr',
                             nargs='*',
                             default=None,
                             required=False,
                             help='A list of AWS regions that will be excluded from producing the energy label.')
    parser.add_argument('--export',
                        '-e',
                        action=ValidatePath,
                        required=False,
                        help='Exports a snapshot of the reporting data in '
                             'JSON formatted files to the specified directory or S3 location.')
    try:
        args = parser.parse_args()
    except argparse.ArgumentTypeError as error:
        print(error)
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
    logging.getLogger('botocore').setLevel(logging.ERROR)
    try:
        print(text2art("AWS Energy Labeler"))
        labeler = EnergyLabeler(args.landing_zone_name,
                                args.region,
                                args.frameworks,
                                allow_list=args.allow_list,
                                deny_list=args.deny_list,
                                allowed_regions=args.allowed_regions,
                                denied_regions=args.denied_regions)
        if args.log_level == 'debug':
            _ = labeler.landing_zone_energy_label
        else:
            with yaspin(text="Please wait while retrieving findings...", color="yellow") as spinner:
                _ = labeler.landing_zone_energy_label
            spinner.ok("✅")
    except (NoRegion,
            InvalidOrNoCredentials,
            NoAccess,
            InvalidAccountListProvided,
            InvalidRegionListProvided,
            InvalidFrameworks) as msg:
        LOGGER.error(msg)
        raise SystemExit(1)
    except Exception as msg:
        LOGGER.error(msg)
        raise SystemExit(1)
    try:
        if args.export:
            LOGGER.info(f'Trying to export data to the requested path : {args.export}')
            exporter = DataExporter(labeler)
            exporter.export(args.export)
        table_data = [
            ['Energy label report', ],
            ['Landing Zone:', args.landing_zone_name],
            ['Landing Zone Security Score:', labeler.landing_zone_energy_label],
            ['Labeled Accounts Security Score:', labeler.labeled_accounts_energy_label]
        ]
        table = AsciiTable(table_data)
        print(table.table)
    except Exception as msg:
        LOGGER.error(msg)
        raise SystemExit(1)
    raise SystemExit(0)


if __name__ == '__main__':
    main()
