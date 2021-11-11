import argparse
import json
import os
import os.path
import sys
import tempfile
from urllib.parse import urljoin
from urllib.parse import urlparse
import logging
import boto3
from awsenergylabelerlib import EnergyLabeler

LOGGER_BASENAME = '''awsenergylabelreporter'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())

FILENAMES = {
    'energy_label': 'energylabel-of-landingzone.json',
    'findings': 'securityhub-findings.json',
    'labeled_accounts': 'labeled-accounts.json'
}


class EnergyLabelFileData:

    def __init__(self, filename, data):
        self.filename = filename
        self.data = data

    def export_as_json_to_fs(self, directory):
        if not (os.path.exists(directory)):
            os.makedirs(directory)
        filepath = os.path.join(directory, self.filename)
        with open(filepath, 'w') as jsonfile:
            json.dump(self.data, jsonfile, indent=2, default=str)
        LOGGER.debug(f'File {self.filename} copied to {directory}')

    def export_as_json_to_s3(self, s3_url):
        s3 = boto3.client('s3')
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


class EnergyLabelExporter:

    def __init__(self, energy_labeler):
        self.energy_labeler = energy_labeler
        self._export_data = None

    def _prepare_export_data(self):
        if self._export_data is None:
            self._export_data = [
                EnergyLabelFileData(
                    FILENAMES['energy_label'],
                    [{'Landing Zone': self.energy_labeler.landing_zone_name,
                      'Landing Zone Energy Label': self.energy_labeler.energy_label_of_landing_zone}]
                ),
                EnergyLabelFileData(
                    FILENAMES['findings'],
                    [finding for finding in self.energy_labeler.get_findings_data_for_frameworks]
                ),
                EnergyLabelFileData(
                    FILENAMES['labeled_accounts'],
                    [account.data for account in self.energy_labeler.labeled_accounts]
                )]
        return self._export_data

    def export_as_json_to_fs(self, directory):
        LOGGER.debug(f'Exporting files to directory {directory}')
        export_data = self._prepare_export_data()
        for f in export_data:
            f.export_as_json_to_fs(directory)

    def export_as_json_to_s3(self, s3_url):
        LOGGER.debug(f'Exporting files to S3 location {s3_url}')
        export_data = self._prepare_export_data()
        for f in export_data:
            f.export_as_json_to_fs(s3_url)


def setup_logging(log_argument):
    levels = {
        'critical': logging.CRITICAL,
        'error': logging.ERROR,
        'warn': logging.WARNING,
        'warning': logging.WARNING,
        'info': logging.INFO,
        'debug': logging.DEBUG
    }
    level = levels.get(log_argument.lower())
    if level is None:
        raise ValueError(
            f"log level given: {log_argument}"
            f" -- must be one of: {' | '.join(levels.keys())}")
    logging.basicConfig(level=level)


def is_s3_url(url):
    return urlparse(url).scheme == "s3"


def is_directory_path(path):
    parsed_url = urlparse(path)
    return parsed_url.scheme == "" and parsed_url.netloc == "" and len(parsed_url.path) >= 1


def print_to_console(landing_zone_name, landing_zone_energy_label, labeled_accounts_energy_label):
    print(f'Landing Zone: {landing_zone_name}')
    print(f'Landing Zone Security Score: {landing_zone_energy_label}')
    print(f'Labeled Accounts Security Score: {labeled_accounts_energy_label}')


def main():
    parser = argparse.ArgumentParser(description='Reporting tool for AWS Security Hub')
    parser.add_argument('--landingzone', type=str, required=True, help='The name of the Landing Zone.')
    parser.add_argument('--region', default='eu-west-1', type=str, required=False,
                        help='The AWS region, default is eu-west-1')
    parser.add_argument('--frameworks', default='aws-foundational-security-best-practices', nargs='*',
                        help='The list of applicable frameworks: [aws-foundational-security-best-practices, cis], '
                             'default=aws-foundational-security-best-practices')
    parser.add_argument('--allowlist', nargs='*',
                        help='A list of AWS Account IDs for which an energy label will be produced.')
    parser.add_argument('--denylist', nargs='*',
                        help='A list of AWS Account IDs that will be excluded from producing the energy label.')
    parser.add_argument('--export', default='', type=str, required=False,
                        help='Exports a snapshot of the reporting data in '
                             'JSON formatted files to the specified directory or S3 location.')
    parser.add_argument("--log", default="warning", type=str, required=False,
                        help="Provide logging level. Example --log debug', default='warning'")
    args = parser.parse_args()

    setup_logging(args.log)

    LOGGER.debug(f'{sys.argv[0]} has started with arguments: {args}')
    labeler = EnergyLabeler(args.landingzone, args.region, args.frameworks, allow_list=args.allowlist,
                            deny_list=args.denylist)
    if args.export:
        exporter = EnergyLabelExporter(labeler)
        if is_s3_url(args.export):
            exporter.export_as_json_to_s3(args.export)
        elif is_directory_path(args.export):
            exporter.export_as_json_to_fs(args.export)
        else:
            LOGGER.error(f'{args.export} is an invalid path. Example --export /a/directory or --export s3://mybucket/'
                         f'location')
            return 1
    print_to_console(args.landingzone, labeler.landing_zone_energy_label, labeler.labeled_accounts_energy_label)
    return 0


if __name__ == '__main__':
    sys.exit(main())
