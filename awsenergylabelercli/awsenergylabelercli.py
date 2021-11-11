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
import os
import os.path
import sys
import tempfile

from urllib.parse import urljoin, urlparse

import boto3
import coloredlogs

from awsenergylabelerlib import EnergyLabeler

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

FILENAMES = {
    'energy_label': 'energylabel-of-landingzone.json',
    'findings': 'securityhub-findings.json',
    'labeled_accounts': 'labeled-accounts.json'
}


class FileDataExport:
    """Models the data to export."""

    def __init__(self, filename, data):
        self.filename = filename
        self.data = data

    def export_as_json_to_fs(self, directory):
        """Exports as json to local filesystem."""
        if not os.path.exists(directory):
            os.makedirs(directory)
        filepath = os.path.join(directory, self.filename)
        with open(filepath, 'w') as jsonfile:
            json.dump(self.data, jsonfile, indent=2, default=str)
        LOGGER.debug(f'File {self.filename} copied to {directory}')

    def export_as_json_to_s3(self, s3_url):
        """Exports as json to S3 object storage."""
        s3 = boto3.client('s3')  # pylint: disable=invalid-name
        parsed_url = urlparse(s3_url)
        bucket_name = parsed_url.netloc
        dst_path = parsed_url.path
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(self.data)
            temp_file.flush()
            dst_filename = urljoin(dst_path, self.filename)
            s3.upload_file(temp_file.name, bucket_name, dst_filename)
            temp_file.close()
        LOGGER.debug(f'File {self.filename} copied to {s3_url}')


class DataExporter:
    """Export AWS security data."""

    def __init__(self, energy_labeler):
        self.energy_labeler = energy_labeler
        self._export_data = None

    def _prepare_export_data(self):
        if self._export_data is None:
            self._export_data = [
                FileDataExport(
                    FILENAMES['energy_label'],
                    [{'Landing Zone': self.energy_labeler.landing_zone_name,
                      'Landing Zone Energy Label': self.energy_labeler.energy_label_of_landing_zone}]
                ),
                FileDataExport(
                    FILENAMES['findings'], self.energy_labeler.get_findings_data_for_frameworks
                ),
                FileDataExport(
                    FILENAMES['labeled_accounts'],
                    [account.data for account in self.energy_labeler.labeled_accounts]
                )]
        return self._export_data

    def export_as_json_to_fs(self, directory):
        """Exports as json to local filesystem."""
        LOGGER.debug(f'Exporting files to directory {directory}')
        export_data = self._prepare_export_data()
        for out_file in export_data:
            out_file.export_as_json_to_fs(directory)

    def export_as_json_to_s3(self, s3_url):
        """Exports as json to S3 object storage."""
        LOGGER.debug(f'Exporting files to S3 location {s3_url}')
        export_data = self._prepare_export_data()
        for out_file in export_data:
            out_file.export_as_json_to_fs(s3_url)

    @staticmethod
    def is_s3_url(url):
        """Is the url an S3 resource."""
        parsed_url = urlparse(url)
        return parsed_url.scheme == "s3" and len(parsed_url.path) >= 1

    @staticmethod
    def is_directory_path(path):
        """Is the path a directory."""
        parsed_url = urlparse(path)
        return parsed_url.scheme == "" and parsed_url.netloc == "" and len(parsed_url.path) >= 1


def is_fs_or_s3(export_location):
    if DataExporter.is_directory_path(export_location) or DataExporter.is_s3_url(export_location):
        return True
    else:
        raise argparse.ArgumentTypeError(
            f'{export_location} is an invalid export location. '
            f'Example --export /a/directory or --export s3://mybucket/ location')


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
    account_list.add_argument('--allowlist',
                              nargs='*',
                              help='A list of AWS Account IDs for which an energy label will be produced.')
    account_list.add_argument('--denylist',
                              nargs='*',
                              help='A list of AWS Account IDs that will be excluded from producing the energy label.')
    parser.add_argument('--export',
                        default='',
                        type=is_fs_or_s3,
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
    labeler = EnergyLabeler(args.landingzone_name, args.region, args.frameworks, allow_list=args.allowlist,
                            deny_list=args.denylist)
    if args.export:
        exporter = DataExporter(labeler)
        if DataExporter.is_s3_url(args.export):
            exporter.export_as_json_to_s3(args.export)
        else:
            exporter.export_as_json_to_fs(args.export)

    print(f'Landing Zone: {args.landingzone_name}')
    print(f'Landing Zone Security Score: {labeler.landing_zone_energy_label}')
    print(f'Labeled Accounts Security Score: {labeler.labeled_accounts_energy_label}')
    raise SystemExit(0)


if __name__ == '__main__':
    main()
