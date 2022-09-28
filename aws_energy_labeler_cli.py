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

import logging
import json

from art import text2art
from awsenergylabelerlib import DataExporter
from terminaltables import AsciiTable

from awsenergylabelercli import (get_arguments,
                                 setup_logging,
                                 get_landing_zone_reporting_data,
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
                        'export_all_data_flag': args.export_all,
                        'log_level': args.log_level}
    if args.landing_zone_name:
        get_reporting_data = get_landing_zone_reporting_data
        method_arguments.update({'landing_zone_name': args.landing_zone_name,
                                 'allowed_account_ids': args.allowed_account_ids,
                                 'denied_account_ids': args.denied_account_ids})

    else:
        get_reporting_data = get_account_reporting_data
        method_arguments.update({'account_id': args.single_account_id})
    return get_reporting_data(**method_arguments)


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
    try:
        print(text2art("AWS Energy Labeler"))
        report_data, exporter_arguments = _get_reporting_arguments(args)
        if args.export_path:
            LOGGER.info(f'Trying to export data to the requested path : {args.export_path}')
            exporter = DataExporter(**exporter_arguments)
            exporter.export(args.export_path)
        report(report_data, args.to_json)
    except Exception as msg:
        LOGGER.error(msg)
        raise SystemExit(1)
    raise SystemExit(0)


if __name__ == '__main__':
    main()
