#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: awsenergylabelercli.py
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
Main code for awsenergylabelercli.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import argparse
import json
import logging
import logging.config
import os

import coloredlogs
from awsenergylabelerlib import (EnergyLabeler,
                                 AwsAccount,
                                 SecurityHub,
                                 ACCOUNT_THRESHOLDS,
                                 LANDING_ZONE_THRESHOLDS,
                                 DEFAULT_SECURITY_HUB_FILTER,
                                 DEFAULT_SECURITY_HUB_FRAMEWORKS,
                                 ALL_LANDING_ZONE_EXPORT_TYPES,
                                 LANDING_ZONE_METRIC_EXPORT_TYPES,
                                 ALL_ACCOUNT_EXPORT_TYPES,
                                 ACCOUNT_METRIC_EXPORT_TYPES)
from awsenergylabelerlib.validations import (validate_allowed_denied_account_ids,
                                             validate_allowed_denied_regions)

from yaspin import yaspin

from .validators import (ValidatePath,
                         aws_account_id,
                         get_mutually_exclusive_args,
                         security_hub_region)

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
LOGGER_BASENAME = '''awsenergylabelercli'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


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
                        default=os.environ.get('AWS_LABELER_LOG_CONFIG', ''))
    parser.add_argument('--log-level',
                        '-L',
                        help='Provide the log level. Defaults to info.',
                        dest='log_level',
                        action='store',
                        default=os.environ.get('AWS_LABELER_LOG_LEVEL', 'info'),
                        choices=['debug',
                                 'info',
                                 'warning',
                                 'error',
                                 'critical'])
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument('--landing-zone-name',
                       '-n',
                       type=str,
                       default=os.environ.get('AWS_LABELER_LANDING_ZONE_NAME'),
                       help='The name of the Landing Zone to label. '
                            'Mutually exclusive with --single-account-id argument.')
    single_account_action = scope.add_argument('--single-account-id',
                                               '-s',
                                               required=False,
                                               dest='single_account_id',
                                               action='store',
                                               type=aws_account_id,
                                               default=os.environ.get('AWS_LABELER_SINGLE_ACCOUNT_ID'),
                                               help='Run the labeler on a single account. '
                                                    'Mutually exclusive with --landing-zone-name argument.')
    parser.add_argument('--region',
                        '-r',
                        default=os.environ.get('AWS_LABELER_REGION'),
                        type=security_hub_region,
                        required=False,
                        help='The home AWS region, default is None')
    parser.add_argument('--frameworks',
                        '-f',
                        default=os.environ.get('AWS_LABELER_FRAMEWORKS', DEFAULT_SECURITY_HUB_FRAMEWORKS),
                        nargs='*',
                        help='The list of applicable frameworks: \
                                ["aws-foundational-security-best-practices", "cis", "pci-dss"], '
                             'default=["aws-foundational-security-best-practices"]')
    account_list = parser.add_mutually_exclusive_group()
    account_list._group_actions.append(single_account_action)  # pylint: disable=protected-access
    account_list.add_argument('--allowed-account-ids',
                              '-a',
                              nargs='*',
                              default=os.environ.get('AWS_LABELER_ALLOWED_ACCOUNT_IDS'),
                              required=False,
                              help='A list of AWS Account IDs for which an energy label will be produced. '
                                   'Mutually exclusive with --denied-account-ids and --single-account-id arguments.')
    account_list.add_argument('--denied-account-ids',
                              '-d',
                              nargs='*',
                              default=os.environ.get('AWS_LABELER_DENIED_ACCOUNT_IDS'),
                              required=False,
                              help='A list of AWS Account IDs that will be excluded from producing the energy label. '
                                   'Mutually exclusive with --allowed-account-ids and --single-account-id arguments.')
    region_list = parser.add_mutually_exclusive_group()
    region_list.add_argument('--allowed-regions',
                             '-ar',
                             nargs='*',
                             default=os.environ.get('AWS_LABELER_ALLOWED_REGIONS'),
                             required=False,
                             help='A list of AWS regions included in producing the energy label.'
                                  'Mutually exclusive with --denied-regions argument.')
    region_list.add_argument('--denied-regions',
                             '-dr',
                             nargs='*',
                             default=os.environ.get('AWS_LABELER_DENIED_REGIONS'),
                             required=False,
                             help='A list of AWS regions excluded from producing the energy label.'
                                  'Mutually exclusive with --allowed-regions argument.')
    parser.add_argument('--export-path',
                        '-p',
                        action=ValidatePath,
                        required=False,
                        default=os.environ.get('AWS_LABELER_EXPORT_PATH'),
                        help='Exports a snapshot of chosen data in '
                             'JSON formatted files to the specified directory or S3 location.')
    export_options = parser.add_mutually_exclusive_group()
    export_options.add_argument('--export-metrics',
                                '-em',
                                action='store_const',
                                dest='export_all',
                                const=False,
                                default=os.environ.get('AWS_LABELER_EXPORT_METRICS'),
                                help='Exports metrics/statistics without sensitive findings data in '
                                     'JSON formatted files to the specified directory or S3 location.')
    export_options.add_argument('--export-all',
                                '-ea',
                                action='store_const',
                                dest='export_all',
                                const=True,
                                default=os.environ.get('AWS_LABELER_EXPORT_ALL', True),
                                help='Exports metrics/statistics along with sensitive findings data in '
                                     'JSON formatted files to the specified directory or S3 location.')
    parser.add_argument('--to-json',
                        '-j',
                        dest='to_json',
                        action='store_true',
                        required=False,
                        default=os.environ.get('AWS_LABELER_TO_JSON', False),
                        help='Return the report in json format.')
    parser.set_defaults(export_all=True)
    args = parser.parse_args()
    args.landing_zone_name, args.single_account_id = get_mutually_exclusive_args(args.landing_zone_name,
                                                                                 args.single_account_id,
                                                                                 required=True)
    args.allowed_account_ids, args.denied_account_ids = validate_allowed_denied_account_ids(args.allowed_account_ids,
                                                                                            args.denied_account_ids)
    args.allowed_regions, args.denied_regions = validate_allowed_denied_regions(args.allowed_regions,
                                                                                args.denied_regions)
    args.frameworks = SecurityHub.validate_frameworks(args.frameworks)
    return args


def setup_logging(level, config_file=None):
    """Sets up the logging.

    Args:
        level: At which level do we log
        config_file: Configuration to use

    """
    # This will configure the logging, if the user has set a config file.
    # If there's no config file, logging will default to stdout.
    if config_file:
        try:
            with open(config_file) as conf_file:
                configuration = json.loads(conf_file.read())
                logging.config.dictConfig(configuration)
        except ValueError:
            print(f'File "{config_file}" is not valid json, cannot continue.')
            raise SystemExit(1)
        except FileNotFoundError:
            print(f'File "{config_file}" does not exist or cannot be read, cannot continue.')
            raise SystemExit(1)
    else:
        coloredlogs.install(level=level.upper())


def wait_for_findings(method_name, method_argument, log_level):
    """If log level is not debug shows a spinner while the callable provided gets security hub findings.

    Args:
        method_name: The method to execute while waiting.
        method_argument: The argument to pass to the method.
        log_level: The log level as set by the user.

    Returns:
        findings: A list of security hub findings as retrieved by the callable.

    """
    try:
        if not log_level == 'debug':
            with yaspin(text="Please wait while retrieving Security Hub findings...", color="yellow") as spinner:
                findings = method_name(method_argument)
            spinner.ok("✅")
        else:
            findings = method_name(method_argument)
    except Exception as msg:
        LOGGER.error(msg)
        raise SystemExit(1)
    return findings


#  pylint: disable=too-many-arguments
def get_landing_zone_reporting_data(landing_zone_name,
                                    region,
                                    frameworks,
                                    allowed_account_ids,
                                    denied_account_ids,
                                    allowed_regions,
                                    denied_regions,
                                    export_all_data_flag,
                                    log_level):
    """Gets the reporting data for a landing zone.

    Args:
        landing_zone_name: The name of the landing zone.
        region: The home region of AWS.
        frameworks: The frameworks to include in scoring.
        allowed_account_ids: The allowed account ids for landing zone inclusion if any.
        denied_account_ids: The allowed account ids for landing zone exclusion if any.
        allowed_regions: The allowed regions for security hub if any.
        denied_regions: The denied regions for security hub if any.
        export_all_data_flag: If set all data is going to be exported, else only basic reporting.
        log_level: The log level set.

    Returns:
        report_data, exporter_arguments

    """
    labeler = EnergyLabeler(landing_zone_name=landing_zone_name,
                            region=region,
                            account_thresholds=ACCOUNT_THRESHOLDS,
                            landing_zone_thresholds=LANDING_ZONE_THRESHOLDS,
                            security_hub_filter=DEFAULT_SECURITY_HUB_FILTER,
                            frameworks=frameworks,
                            allowed_account_ids=allowed_account_ids,
                            denied_account_ids=denied_account_ids,
                            allowed_regions=allowed_regions,
                            denied_regions=denied_regions)
    wait_for_findings(EnergyLabeler.security_hub_findings.fget, labeler, log_level)
    report_data = [['Landing Zone:', labeler.landing_zone.name],
                   ['Landing Zone Security Score:', labeler.landing_zone_energy_label.label],
                   ['Landing Zone Percentage Coverage:', labeler.landing_zone_energy_label.coverage],
                   ['Labeled Accounts Measured:', labeler.labeled_accounts_energy_label.accounts_measured]]
    if not labeler.landing_zone_energy_label.best_label == labeler.landing_zone_energy_label.worst_label:
        report_data.extend([['Best Account Security Score:', labeler.landing_zone_energy_label.best_label],
                            ['Worst Account Security Score:', labeler.landing_zone_energy_label.worst_label]])
    export_types = ALL_LANDING_ZONE_EXPORT_TYPES if export_all_data_flag else LANDING_ZONE_METRIC_EXPORT_TYPES
    exporter_arguments = {'export_types': export_types,
                          'name': labeler.landing_zone.name,
                          'energy_label': labeler.landing_zone_energy_label.label,
                          'security_hub_findings': labeler.security_hub_findings,
                          'labeled_accounts': labeler.landing_zone_labeled_accounts}
    return report_data, exporter_arguments


#  pylint: disable=too-many-arguments
def get_account_reporting_data(account_id,
                               region,
                               frameworks,
                               allowed_regions,
                               denied_regions,
                               export_all_data_flag,
                               log_level):
    """Gets the reporting data for a single account.

    Args:
        account_id: The ID of the account to get reporting on.
        region: The home region of AWS.
        frameworks: The frameworks to include in scoring.
        allowed_regions: The allowed regions for security hub if any.
        denied_regions: The denied regions for security hub if any.
        export_all_data_flag: If set all data is going to be exported, else only basic reporting.
        log_level: The log level set.

    Returns:
        report_data, exporter_arguments

    """
    account = AwsAccount(account_id, 'Not Retrieved', ACCOUNT_THRESHOLDS)
    security_hub = SecurityHub(region=region,
                               allowed_regions=allowed_regions,
                               denied_regions=denied_regions)
    query_filter = SecurityHub.calculate_query_filter(DEFAULT_SECURITY_HUB_FILTER,
                                                      allowed_account_ids=[account_id],
                                                      denied_account_ids=None,
                                                      frameworks=frameworks)
    security_hub_findings = wait_for_findings(security_hub.get_findings, query_filter, log_level)
    account.calculate_energy_label(security_hub_findings)
    report_data = [['Account ID:', account.id],
                   ['Account Security Score:', account.energy_label.label],
                   ['Number Of Critical & High Findings:', account.energy_label.number_of_critical_high_findings],
                   ['Number Of Medium Findings:', account.energy_label.number_of_medium_findings],
                   ['Number Of Low Findings:', account.energy_label.number_of_low_findings],
                   ['Max Days Open:', account.energy_label.max_days_open]]
    if account.alias:
        report_data.append(['Account Alias:', account.alias])
    export_types = ALL_ACCOUNT_EXPORT_TYPES if export_all_data_flag else ACCOUNT_METRIC_EXPORT_TYPES
    exporter_arguments = {'export_types': export_types,
                          'name': account.id,
                          'energy_label': account.energy_label.label,
                          'security_hub_findings': security_hub_findings,
                          'labeled_accounts': account}
    return report_data, exporter_arguments
