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
import hashlib
import os

import coloredlogs
from yaspin import yaspin
from awsenergylabelerlib import (validate_regions,
                                 validate_account_ids,
                                 AwsAccount,
                                 EnergyLabeler,
                                 DestinationPath,
                                 SecurityHub,
                                 ACCOUNT_THRESHOLDS,
                                 ZONE_THRESHOLDS,
                                 DEFAULT_SECURITY_HUB_FILTER,
                                 DEFAULT_SECURITY_HUB_FRAMEWORKS,
                                 ALL_ZONE_EXPORT_TYPES,
                                 ZONE_METRIC_EXPORT_TYPES,
                                 ALL_ACCOUNT_EXPORT_TYPES,
                                 ACCOUNT_METRIC_EXPORT_TYPES,
                                 InvalidFrameworks,
                                 InvalidAccountListProvided,
                                 InvalidRegionListProvided)

from ._version import __version__ as cli_version
from .awsenergylabelercliexceptions import MissingRequiredArguments, MutuallyExclusiveArguments
from .validators import (account_thresholds_config,
                         aws_account_id,
                         character_delimited_list_variable,
                         environment_variable_boolean,
                         default_environment_variable,
                         get_mutually_exclusive_args,
                         json_string,
                         positive_integer,
                         security_hub_region,
                         valid_local_file,
                         zone_thresholds_config,
                         OverridingArgument)

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

SUPPRESSED_FINDINGS_QUERY = {'WorkflowStatus': [{'Value': 'SUPPRESSED',
                                                 'Comparison': 'EQUALS'}]}

RESOLVED_FINDINGS_QUERY = lambda x: {'UpdatedAt': [{'DateRange': {'Value': x, 'Unit': 'DAYS'}}],  # noqa
                                     'WorkflowStatus': [{'Value': 'RESOLVED', 'Comparison': 'EQUALS'}]}


def get_parser():
    """Constructs the parser with all the arguments and returns it."""
    # https://docs.python.org/3/library/argparse.html
    parser = argparse.ArgumentParser(description='''A cli to label accounts and security zones with energy labels based
    on Security Hub findings.''')
    parser.add_argument('--log-config',
                        '-l',
                        action=default_environment_variable('AWS_LABELER_LOG_CONFIG'),
                        dest='logger_config',
                        help='The location of the logging config json file')
    parser.add_argument('--log-level',
                        '-L',
                        help='Provide the log level. Defaults to info.',
                        dest='log_level',
                        action=default_environment_variable('AWS_LABELER_LOG_LEVEL'),
                        default='info',
                        choices=['debug',
                                 'info',
                                 'warning',
                                 'error',
                                 'critical'])
    parser.add_argument('--region',
                        '-r',
                        action=default_environment_variable('AWS_LABELER_REGION'),
                        type=security_hub_region,
                        required=True,
                        help='The home AWS region, default is looking into the environment for either '
                             '"AWS_LABELER_REGION" or "AWS_DEFAULT_REGION" variables.')
    parser.add_argument('--organizations-zone-name',
                        '-o',
                        action=default_environment_variable('AWS_LABELER_ORGANIZATIONS_ZONE_NAME'),
                        help='The name of the Organizations Zone to label. Implies access to organizations api in aws.'
                             'Mutually exclusive with --single-account-id argument and --audit-zone-name.')
    parser.add_argument('--audit-zone-name',
                        '-z',
                        action=default_environment_variable('AWS_LABELER_AUDIT_ZONE_NAME'),
                        help='The name of the Audit Zone to label. Does not need access to organizations api in aws, '
                             'retrieves accounts from security hub, will not report on the audit account itself.'
                             'Mutually exclusive with --single-account-id argument and --organizations-zone-name.')
    parser.add_argument('--single-account-id',
                        '-s',
                        type=aws_account_id,
                        action=default_environment_variable('AWS_LABELER_SINGLE_ACCOUNT_ID'),
                        help='Run the labeler on a single account. '
                             'Mutually exclusive with --organizations-zone-name and '
                             '--audit-zone-name argument.')
    parser.add_argument('--frameworks',
                        '-f',
                        default=os.environ.get('AWS_LABELER_FRAMEWORKS', DEFAULT_SECURITY_HUB_FRAMEWORKS),
                        type=character_delimited_list_variable,
                        help='The list of applicable frameworks: ["aws-foundational-security-best-practices", '
                             '"cis", "pci-dss"], default=["aws-foundational-security-best-practices"]. '
                             'Setting the flag with an empty string argument will set no frameworks for filters.')
    parser.add_argument('--allowed-account-ids',
                        '-a',
                        action=default_environment_variable('AWS_LABELER_ALLOWED_ACCOUNT_IDS'),
                        type=character_delimited_list_variable,
                        help='A list of AWS Account IDs for which an energy label will be produced. '
                             'Mutually exclusive with --denied-account-ids and --single-account-id arguments.')
    parser.add_argument('--denied-account-ids',
                        '-d',
                        action=default_environment_variable('AWS_LABELER_DENIED_ACCOUNT_IDS'),
                        type=character_delimited_list_variable,
                        help='A list of AWS Account IDs that will be excluded from producing the energy label. '
                             'Mutually exclusive with --allowed-account-ids and --single-account-id arguments.')
    parser.add_argument('--allowed-regions',
                        '-ar',
                        action=default_environment_variable('AWS_LABELER_ALLOWED_REGIONS'),
                        type=character_delimited_list_variable,
                        help='A list of AWS regions included in producing the energy label.'
                             'Mutually exclusive with --denied-regions argument.')
    parser.add_argument('--denied-regions',
                        '-dr',
                        action=default_environment_variable('AWS_LABELER_DENIED_REGIONS'),
                        type=character_delimited_list_variable,
                        help='A list of AWS regions excluded from producing the energy label.'
                             'Mutually exclusive with --allowed-regions argument.')
    parser.add_argument('--export-path',
                        '-p',
                        action=default_environment_variable('AWS_LABELER_EXPORT_PATH'),
                        help='Exports a snapshot of chosen data in '
                             'JSON formatted files to the specified directory or S3 location.')
    parser.add_argument('--export-metrics-only',
                        '-e',
                        dest='export_all',
                        action='store_false',
                        help='Exports metrics/statistics without sensitive findings data if set, in JSON formatted '
                             'files to the specified directory or S3 location, default is export all data.')
    parser.add_argument('--to-json',
                        '-j',
                        action='store_true',
                        default=environment_variable_boolean(os.environ.get('AWS_LABELER_TO_JSON', False)),
                        help='Return the report in json format.')
    parser.add_argument('--report-closed-findings-days',
                        '-rd',
                        action='store',
                        required=False,
                        default=os.environ.get('AWS_LABELER_REPORT_CLOSED_FINDINGS_DAYS'),
                        type=positive_integer,
                        help='If set the report will contain info on the number of findings that were closed during the'
                             ' provided days count')
    parser.add_argument('--report-suppressed-findings',
                        '-rs',
                        action='store_true',
                        default=environment_variable_boolean(os.environ.get('AWS_LABELER_REPORT_SUPPRESSED_FINDINGS',
                                                                            False)),
                        help='If set the report will contain info on the number of suppressed findings')
    parser.add_argument('--account-thresholds',
                        '-at',
                        type=account_thresholds_config,
                        default=os.environ.get('AWS_LABELER_ACCOUNT_THRESHOLDS'),
                        help='If set the account thresholds will be used instead of the default ones.')
    parser.add_argument('--zone-thresholds',
                        '-zt',
                        type=zone_thresholds_config,
                        default=os.environ.get('AWS_LABELER_ZONE_THRESHOLDS'),
                        help='If set the zone thresholds will be used instead of the default ones.')
    parser.add_argument('--security-hub-query-filter',
                        '-sf',
                        type=json_string,
                        default=os.environ.get('AWS_LABELER_SECURITY_HUB_QUERY_FILTER'),
                        help='If set the zone thresholds will be used instead of the default ones.')
    parser.add_argument('--validate-metadata-file',
                        '-vm',
                        action=OverridingArgument,
                        type=valid_local_file,
                        help='Validates a metadata file. Warning, if this argument is set any other argument is '
                             'effectively disregarded and only the file provided is processed.')
    parser.add_argument('--version',
                        '-v',
                        action=OverridingArgument,
                        nargs=0,
                        help='Prints the version of the tool.')
    parser.set_defaults(export_all=True)
    return parser


def calculate_file_hash(binary_contents):
    """Calculates a hex digest of binary contents.

    Args:
        binary_contents: The binary object to calculate the hex digest of.

    Returns:
        The calculated hex digest of the binary object.

    """
    hash_object = hashlib.sha256()
    hash_object.update(binary_contents)
    return hash_object.hexdigest()


def validate_metadata_file(file_path, parser):
    """Validates a provided local metadata file by looking into its contents.

    Args:
        file_path: The local file path of the file to validate for.
        parser: The parser to use the appropriate exit methods.

    Returns:
        parser.exit(0) on success

    Raises:
        parser.error on failure.

    """
    try:
        with open(file_path, 'r') as ifile:
            LOGGER.debug(f'Received local file "{file_path}" to validate.')
            contents = ifile.read()
            data = json.loads(contents)
            recorded_hash = data.get('Hash:')
            if not recorded_hash:
                parser.error(f'Local file "{file_path}" does not have a "Hash:" entry!')
            del data['Hash:']
            calculated_hash = calculate_file_hash(json.dumps(data).encode('utf-8'))
            if recorded_hash == calculated_hash:
                parser.exit(0, f'The file {file_path} seems a valid metadata file.')
    except (ValueError, AttributeError):
        parser.error(f'Local file "{file_path}" provided is not a valid json file!')
    parser.error(f'The recorded hash {recorded_hash} does not match the calculated one {calculated_hash}!')


def get_arguments(arguments=None):  # noqa: MC0001
    """
    Gets us the cli arguments.

    Returns the args as parsed from the argsparser.
    """
    parser = get_parser()
    args = parser.parse_args(arguments)
    if args.version:
        parser.exit(0, cli_version)
    if args.validate_metadata_file:
        # if overriding argument is set then we do not check any other arguments and we exit straight
        # after validating the argument
        raise validate_metadata_file(args.validate_metadata_file, parser)
    # Since mutual exclusive cannot work with environment variables we need to check explicitly for all pairs of
    # mutual relations that are not allowed.
    if all([args.allowed_account_ids, args.denied_account_ids]):
        raise parser.error('argument --allowed-account-ids/-a: not allowed with argument --denied-account-ids/-d')
    if all([args.allowed_regions, args.denied_regions]):
        raise parser.error('argument --allowed-regions/-ar: not allowed with argument --denied-regions/-dr')
    export_metrics_set = environment_variable_boolean(os.environ.get('AWS_LABELER_EXPORT_ONLY_METRICS'))
    if export_metrics_set:
        args.export_all = False
    exclusive_args = [args.organizations_zone_name, args.audit_zone_name, args.single_account_id]
    try:
        _ = get_mutually_exclusive_args(*exclusive_args, required=True)
    except MissingRequiredArguments:
        raise parser.error('one of the arguments --organizations-zone-name/-o --audit-zone-name/-z '
                           '--single-account-id/-s is required')
    except MutuallyExclusiveArguments:
        raise parser.error('arguments --organizations-zone-name/-o --audit-zone-name/-z '
                           '--single-account-id/-s are mutually exclusive')
    exclusive_args = [args.allowed_account_ids, args.denied_account_ids, args.single_account_id]
    try:
        _ = get_mutually_exclusive_args(*exclusive_args)
    except MutuallyExclusiveArguments:
        raise parser.error('arguments --allowed-account-ids/-a --denied-account-ids/-d --single-account-id/-s are '
                           'mutually exclusive')
    try:
        SecurityHub.validate_frameworks(args.frameworks)
    except InvalidFrameworks:
        raise parser.error(f'{args.frameworks} are not valid supported security hub frameworks. Currently supported '
                           f'are {SecurityHub.frameworks}')
    for argument in ['allowed_account_ids', 'denied_account_ids']:
        try:
            _ = validate_account_ids(getattr(args, argument))
        except InvalidAccountListProvided:
            raise parser.error(f'{getattr(args, argument)} contains invalid account ids.')
    for argument in ['allowed_regions', 'denied_regions']:
        try:
            _ = validate_regions(getattr(args, argument))
        except InvalidRegionListProvided:
            raise parser.error(f'{getattr(args, argument)} contains invalid regions.')
    if args.export_path and not DestinationPath(args.export_path).is_valid():
        raise parser.error(f'{args.export_path} is an invalid export location. Example --export-path '
                           f'/a/directory or --export-path s3://mybucket location')
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


def wait_for_findings(method_name, method_argument, log_level, finding_type=None):
    """If log level is not debug shows a spinner while the callable provided gets security hub findings.

    Args:
        method_name: The method to execute while waiting.
        method_argument: The argument to pass to the method.
        log_level: The log level as set by the user.
        finding_type: The type of the finding to use for the helping message.

    Returns:
        findings: A list of security hub findings as retrieved by the callable.

    """
    try:
        if log_level != 'debug':
            with yaspin(text=f"Please wait while retrieving Security Hub{f' {finding_type} ' if finding_type else ' '}"
                             f"findings...", color="yellow") as spinner:
                findings = method_name(method_argument) if method_argument else method_name()
            spinner.ok("✅")
        else:
            findings = method_name(method_argument) if method_argument else method_name()
    except Exception as msg:
        LOGGER.error(msg)
        raise SystemExit(1)
    return findings


#  pylint: disable=too-many-arguments,too-many-locals
def get_zone_reporting_data(zone_name,
                            region,
                            frameworks,
                            allowed_account_ids,
                            denied_account_ids,
                            allowed_regions,
                            denied_regions,
                            export_all_data_flag,
                            report_closed_findings_days,
                            report_suppressed_findings,
                            account_thresholds,
                            zone_thresholds,
                            security_hub_query_filter,
                            log_level,
                            zone_type):
    """Gets the reporting data for an organizations zone.

    Args:
        zone_name: The name of the security zone.
        region: The home region of AWS.
        frameworks: The frameworks to include in scoring.
        allowed_account_ids: The allowed account ids for landing zone inclusion if any.
        denied_account_ids: The allowed account ids for landing zone exclusion if any.
        allowed_regions: The allowed regions for security hub if any.
        denied_regions: The denied regions for security hub if any.
        export_all_data_flag: If set all data is going to be exported, else only basic reporting.
        report_closed_findings_days:
        report_suppressed_findings:
        account_thresholds:
        zone_thresholds:
        log_level: The log level set.
        zone_type: The type of zone to label.

    Returns:
        report_data, exporter_arguments

    """
    labeler = EnergyLabeler(zone_name=zone_name,
                            region=region,
                            account_thresholds=account_thresholds or ACCOUNT_THRESHOLDS,
                            zone_thresholds=zone_thresholds or ZONE_THRESHOLDS,
                            security_hub_filter=security_hub_query_filter or DEFAULT_SECURITY_HUB_FILTER,
                            frameworks=frameworks,
                            allowed_account_ids=allowed_account_ids,
                            denied_account_ids=denied_account_ids,
                            allowed_regions=allowed_regions,
                            denied_regions=denied_regions,
                            zone_type=zone_type)
    wait_for_findings(EnergyLabeler.security_hub_findings.fget, labeler, log_level)
    report_data = [['Zone:', labeler.zone.name],
                   ['Zone Security Score:', labeler.zone_energy_label.label],
                   ['Zone Percentage Coverage:', labeler.zone_energy_label.coverage],
                   ['Labeled Accounts Measured:', labeler.labeled_accounts_energy_label.accounts_measured]]
    if labeler.zone_energy_label.best_label != labeler.zone_energy_label.worst_label:
        report_data.extend([['Best Account Security Score:', labeler.zone_energy_label.best_label],
                            ['Worst Account Security Score:', labeler.zone_energy_label.worst_label]])
    if report_closed_findings_days:
        LOGGER.warning('Reporting on resolved findings is not functional yet.')
        # query_filter = labeler.security_hub.calculate_query_filter(RESOLVED_FINDINGS_QUERY(
        #                                                                report_closed_findings_days),
        #                                                            allowed_account_ids=allowed_account_ids,
        #                                                            denied_account_ids=denied_account_ids,
        #                                                            frameworks=frameworks)
        # resolved_findings = wait_for_findings(labeler.security_hub.get_findings,
        #                                       query_filter,
        #                                       log_level,
        #                                       'resolved')
        # report_data.append([f'Resolved Findings Last {report_closed_findings_days} Days:', len(resolved_findings)])
    if report_suppressed_findings:
        query_filter = labeler.security_hub.calculate_query_filter(SUPPRESSED_FINDINGS_QUERY,
                                                                   allowed_account_ids=allowed_account_ids,
                                                                   denied_account_ids=denied_account_ids,
                                                                   frameworks=frameworks)
        suppressed_findings = wait_for_findings(labeler.security_hub.get_findings,
                                                query_filter,
                                                log_level,
                                                'suppressed')
        report_data.append(['Suppressed Findings:', len(suppressed_findings)])
    export_types = ALL_ZONE_EXPORT_TYPES if export_all_data_flag else ZONE_METRIC_EXPORT_TYPES
    exporter_arguments = {'export_types': export_types,
                          'name': labeler.zone.name,
                          'energy_label': labeler.zone_energy_label.label,
                          'security_hub_findings': labeler.security_hub_findings,
                          'labeled_accounts': labeler.zone_labeled_accounts}
    return report_data, exporter_arguments


#  pylint: disable=too-many-arguments,too-many-locals
def get_account_reporting_data(account_id,
                               region,
                               frameworks,
                               allowed_regions,
                               denied_regions,
                               export_all_data_flag,
                               report_closed_findings_days,
                               report_suppressed_findings,
                               account_thresholds,
                               security_hub_query_filter,
                               log_level):
    """Gets the reporting data for a single account.

    Args:
        account_id: The ID of the account to get reporting on.
        region: The home region of AWS.
        frameworks: The frameworks to include in scoring.
        allowed_regions: The allowed regions for security hub if any.
        denied_regions: The denied regions for security hub if any.
        export_all_data_flag: If set all data is going to be exported, else only basic reporting.
        report_closed_findings_days: The number of days to report the resolved findings for.
        report_suppressed_findings: A flag to report on suppressed findings or not.
        account_thresholds: The account thresholds to apply.
        security_hub_query_filter: The security hub filter to apply.
        log_level: The log level set.

    Returns:
        report_data, exporter_arguments

    """
    account = AwsAccount(account_id, account_thresholds or ACCOUNT_THRESHOLDS, 'Not Retrieved')
    security_hub = SecurityHub(region=region,
                               allowed_regions=allowed_regions,
                               denied_regions=denied_regions)
    query_filter = SecurityHub.calculate_query_filter(security_hub_query_filter or DEFAULT_SECURITY_HUB_FILTER,
                                                      allowed_account_ids=[account_id],
                                                      denied_account_ids=None,
                                                      frameworks=frameworks)
    unfiltered_findings = wait_for_findings(security_hub.get_findings, query_filter, log_level)
    security_hub_findings = security_hub.filter_findings_by_frameworks(unfiltered_findings, frameworks)
    account.calculate_energy_label(security_hub_findings)
    report_data = [['Account ID:', account.id],
                   ['Account Security Score:', account.energy_label.label],
                   ['Number Of Critical Findings:', account.energy_label.number_of_critical_findings],
                   ['Number Of High Findings:', account.energy_label.number_of_high_findings],
                   ['Number Of Medium Findings:', account.energy_label.number_of_medium_findings],
                   ['Number Of Low Findings:', account.energy_label.number_of_low_findings],
                   ['Max Days Open:', account.energy_label.max_days_open]]
    if account.alias:
        report_data.append(['Account Alias:', account.alias])
    if report_closed_findings_days:
        LOGGER.warning('Reporting on resolved findings is not functional yet.')
        # query_filter = SecurityHub.calculate_query_filter(RESOLVED_FINDINGS_QUERY(report_closed_findings_days),
        #                                                   allowed_account_ids=[account_id],
        #                                                   denied_account_ids=None,
        #                                                   frameworks=frameworks)
        # resolved_findings = wait_for_findings(security_hub.get_findings,
        #                                       query_filter,
        #                                       log_level,
        #                                       'resolved')
        # report_data.append([f'Resolved Findings Last {report_closed_findings_days} Days:', len(resolved_findings)])
    if report_suppressed_findings:
        query_filter = SecurityHub.calculate_query_filter(SUPPRESSED_FINDINGS_QUERY,
                                                          allowed_account_ids=[account_id],
                                                          denied_account_ids=None,
                                                          frameworks=frameworks)
        suppressed_findings = wait_for_findings(security_hub.get_findings, query_filter, log_level, 'suppressed')
        report_data.append(['Suppressed Findings:', len(suppressed_findings)])
    export_types = ALL_ACCOUNT_EXPORT_TYPES if export_all_data_flag else ACCOUNT_METRIC_EXPORT_TYPES
    exporter_arguments = {'export_types': export_types,
                          'name': account.id,
                          'energy_label': account.energy_label.label,
                          'security_hub_findings': security_hub_findings,
                          'labeled_accounts': account}
    return report_data, exporter_arguments
