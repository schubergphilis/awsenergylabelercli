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
import datetime
import json
import logging

from art import text2art
from terminaltables import AsciiTable
from awsenergylabelerlib import DataExporter
from awsenergylabelerlib._version import __version__ as lib_version
from awsenergylabelercli._version import __version__ as cli_version

from awsenergylabelercli import (get_arguments,
                                 setup_logging,
                                 get_zone_reporting_data,
                                 get_account_reporting_data)

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


def _get_reporting_arguments(args):
    method_arguments = {'region': args.region,
                        'frameworks': args.frameworks,
                        'allowed_regions': args.allowed_regions,
                        'denied_regions': args.denied_regions,
                        'report_closed_findings_days': args.report_closed_findings_days,
                        'report_suppressed_findings': args.report_suppressed_findings,
                        'account_thresholds': args.account_thresholds,
                        'export_all_data_flag': args.export_all,
                        'security_hub_query_filter': args.security_hub_query_filter,
                        'log_level': args.log_level}
    start_run_time = datetime.datetime.now()
    if args.single_account_id:
        get_reporting_data = get_account_reporting_data
        method_arguments.update({'account_id': args.single_account_id})
    else:
        zone_type = 'organizations_zone' if args.organizations_zone_name else 'audit_zone'
        zone_name = args.organizations_zone_name or args.audit_zone_name
        get_reporting_data = get_zone_reporting_data
        method_arguments.update({'zone_name': zone_name,
                                 'allowed_account_ids': args.allowed_account_ids,
                                 'denied_account_ids': args.denied_account_ids,
                                 'zone_type': zone_type,
                                 'zone_thresholds': args.zone_thresholds})
    report_data, exporter_arguments = get_reporting_data(**method_arguments)
    report_data.append(['Default Account Thresholds Overwritten:', True if args.account_thresholds else False])
    if any([args.organizations_zone_name, args.audit_zone_name]):
        report_data.append(['Default Zone Thresholds Overwritten:', True if args.zone_thresholds else False])
    report_data.append(['Default Security Hub Query Filter Overwritten:',
                        True if args.security_hub_query_filter else False])
    end_run_time = datetime.datetime.now()
    report_data.extend([['Library Version:', lib_version],
                        ['Cli Version:', cli_version],
                        ['Date and time of execution:', str(end_run_time)],
                        ['Duration of run:', str(end_run_time - start_run_time)]])
    return report_data, exporter_arguments


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


def main():
    """Main method."""
    args = get_arguments()
    setup_logging(args.log_level, args.logger_config)
    logging.getLogger('botocore').setLevel(logging.ERROR)
    for entity in ['account', 'zone']:
        if getattr(args, f'{entity}_thresholds'):
            LOGGER.warning(f'{entity.capitalize()} thresholds have been overwritten, '
                           f'configuration will be reported on the output.')
    if not args.frameworks:
        LOGGER.info('No frameworks have been provided for filtering.')
    # print(args)
    # print(sys.argv)
    try:
        print(text2art("AWS Energy Labeler"))
        report_data, exporter_arguments = _get_reporting_arguments(args)
        if args.export_path:
            LOGGER.info(f'Trying to export data to the requested path : {args.export_path}')
            exporter = DataExporter(**exporter_arguments)
            exporter.export(args.export_path)
        report(report_data, args.to_json)
        status_code = 0
    except Exception as msg:  # pylint: disable=broad-except
        LOGGER.error(msg)
        status_code = 1
    return status_code


if __name__ == '__main__':
    raise SystemExit(main())
