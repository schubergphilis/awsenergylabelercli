#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: aws_energy_labeler_cli.py
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
Main code for aws_energy_labeler_cli.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import json
import logging

import typer
from art import text2art
from awsenergylabelerlib import DataExporter
from terminaltables import AsciiTable

from awsenergylabelercli import (get_account_reporting_data,
                                 get_landing_zone_reporting_data,
                                 setup_logging)
from awsenergylabelercli.awsenergylabelercliexceptions import \
    MissingRequiredArgument
from awsenergylabelercli.validators import (get_mutually_exclusive,
                                            validate_path)

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''11-11-2021'''
__copyright__ = '''Copyright 2022, Costas Tyfoxylos'''
__credits__ = ["Theodoor Scholte", "Costas Tyfoxylos", "Jenda Brands"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is the main prefix used for logging
LOGGER_BASENAME = '''aws_energy_labeler_cli'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


def report(report_data, to_json=False):
    """Report to table or json."""
    if to_json:
        data = {key.replace(':', '').replace(' ', '_').lower(): value for key, value in dict(report_data).items()}
        print(json.dumps(data, indent=2))
        return None
    table_data = [['Energy label report']]
    table_data.extend(report_data)
    table = AsciiTable(table_data)
    print(table.table)
    return None


#  pylint: disable=too-many-arguments,too-many-locals
def main(logger_config=typer.Option('',
                                    '--log-config',
                                    '-l',
                                    envvar='LOG_CONFIG',
                                    help='The location of the logging config json file'),
         log_level=typer.Option('info',
                                '--log-level',
                                '-L',
                                envvar='LOG_LEVEL',
                                help='Provide the log level. Defaults to info.'),
         landing_zone_name: str = typer.Option(None,
                                               '--landing-zone-name',
                                               '-n',
                                               envvar='LANDING_ZONE_NAME',
                                               help='The name of the Landing Zone to label. '
                                                    'Mutually exclusive with --single-account-id argument.'),
         single_account_id=typer.Option(None,
                                        '--single-account-id',
                                        '-s',
                                        envvar='SINGLE_ACCOUNT_ID',
                                        help='Run the labeler on a single account. '
                                             'Mutually exclusive with --landing-zone-name argument.'),
         region=typer.Option(None,
                             '--region',
                             '-r',
                             envvar='REGION',
                             help='The home AWS region, default is None'),
         frameworks=typer.Option(None,
                                 '--frameworks',
                                 '-f',
                                 help='The list of applicable frameworks: \
                                      ["aws-foundational-security-best-practices", "cis", "pci-dss"], '
                                      'default=["aws-foundational-security-best-practices"]'),
         allowed_account_ids=typer.Option(None,
                                          '--allowed-account-ids',
                                          '-a',
                                          envvar='ALLOWED_ACCOUNT_IDS',
                                          help='A list of AWS Account IDs for which an energy label will be produced. '
                                               'Mutually exclusive with --denied-account-ids and \
                                                --single-account-id arguments.'),
         denied_account_ids=typer.Option(None,
                                         '--denied-account-ids',
                                         '-a',
                                         envvar='ALLOWED_ACCOUNT_IDS',
                                         help='A list of AWS Account IDs for which an energy label will be produced. '
                                              'Mutually exclusive with --denied-account-ids and \
                                               --single-account-id arguments.'),
         allowed_regions=typer.Option(None,
                                      '--allowed-regions',
                                      '-ar',
                                      envvar='ALLOWED_ACCOUNT_IDS',
                                      help='A list of AWS regions included in producing the energy label.'
                                           'Mutually exclusive with --denied-regions argument.'),
         denied_regions=typer.Option(None,
                                     '--denied-regions',
                                     '-dr',
                                     envvar='ALLOWED_ACCOUNT_IDS',
                                     help='A list of AWS regions excluded from producing the energy label.'
                                     'Mutually exclusive with --allowed-regions argument.'),
         export_path=typer.Option(None,
                                  '--export-path',
                                  '-p',
                                  envvar='EXPORT_PATH',
                                  help='Path to export a snapshot of metrics data (by default) in '
                                       'JSON formatted files to the specified directory or S3 location.'
                                       'When [-ea|--export-all] is set, all findings data is exported \
                                        to this location'),
         export_all: bool = typer.Option(None,
                                         '--export-all',
                                         '-ea',
                                         envvar='EXPORT_ALL',
                                         help='Exports all findings data (including sensitive data) in '
                                              'JSON formatted files to the specified directory or S3 location.'
                                              'As set with [-p|--export-path]'),
         to_json: bool = typer.Option(None,
                                      '--to-json',
                                      '-j',
                                      envvar='TO_JSON',
                                      help='Prints metrics/statistics is JSON format instead of table')):
    """Main method."""
    landing_zone_name, single_account_id = get_mutually_exclusive({'landing_zone_name': landing_zone_name,
                                                                   'single_account_id': single_account_id},
                                                                  required=True)
    allowed_account_ids, denied_account_ids = get_mutually_exclusive({'allowed_account_ids': allowed_account_ids,
                                                                      'denied_account_ids': denied_account_ids})
    allowed_regions, denied_regions = get_mutually_exclusive({'allowed_regions': allowed_regions,
                                                              'denied_regions': denied_regions})

    if export_all and not export_path:
        raise MissingRequiredArgument('export_path is required when export_all is set')

    if export_path:
        validate_path(export_path)

    setup_logging(log_level, logger_config)
    logging.getLogger('botocore').setLevel(logging.ERROR)

    try:
        print(text2art("AWS Energy Labeler"))
        method_arguments = {'region': region,
                            'allowed_regions': allowed_regions,
                            'denied_regions': denied_regions,
                            'export_all_data_flag': export_all,
                            'log_level': log_level,
                            'frameworks': frameworks}
        if landing_zone_name:
            get_reporting_data = get_landing_zone_reporting_data
            method_arguments.update({'landing_zone_name': landing_zone_name,
                                     'allowed_account_ids': allowed_account_ids,
                                     'denied_account_ids': denied_account_ids})
        else:
            get_reporting_data = get_account_reporting_data
            method_arguments.update({'account_id': single_account_id})

        report_data, exporter_arguments = get_reporting_data(**method_arguments)

        if export_path:
            LOGGER.info(f'Trying to export data to the requested path : {export_path}')
            exporter = DataExporter(**exporter_arguments)
            exporter.export(export_path)
        report(report_data, to_json)
    except Exception as msg:
        LOGGER.error(msg)
        raise SystemExit(1)
    raise SystemExit(0)


if __name__ == '__main__':
    typer.run(main)
