import argparse
import json
import os
import os.path
import sys
import tempfile
from dataclasses import dataclass
from urllib.parse import urljoin
from urllib.parse import urlparse

import boto3
from awsenergylabelerlib import EnergyLabeler

FILENAMES = {
    'energy_label': "energylabel-of-landingzone.json",
    'findings': "securityhub-findings.json",
    'labeled_accounts': "labeled-accounts.json"
}


class EnergyLabelFileExport:

    def __init__(self, filename, data):
        self.filename = filename
        self.data = data

    def export_as_json_to_fs(self, directory):
        if not (os.path.exists(directory)):
            os.makedirs(directory)
        filepath = os.path.join(directory, self.filename)
        with open(filepath, 'w') as jsonfile:
            json.dump(self.data, jsonfile, indent=2, default=str)

    def export_as_json_to_s3(self, s3_url):
        s3 = boto3.client('s3')
        parsed_url = urlparse.urlparse(s3_url)
        bucket_name = parsed_url.netloc
        dst_path = parsed_url.path

        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(self.data)
            temp_file.flush()
            dst_filename = urljoin(dst_path, self.filename)
            s3.upload_file(temp_file.name, bucket_name, dst_filename)
            temp_file.close()


class EnergyLabelReporter:

    def __init__(self, landing_zone_name, allow_list, deny_list):
        self.landing_zone_name = landing_zone_name
        self.labeler = EnergyLabeler(landing_zone_name, allow_list=allow_list, deny_list=deny_list)

        self.export_configurations = [
            ExportConfiguration(FILENAMES['energy_label'],
                                [{'Landing Zone': self.landing_zone_name,
                                  'Landing Zone Energy Label': self.labeler.energy_label_of_landing_zone}]
                                ),
            ExportConfiguration(
                FILENAMES['findings'],
                [finding.data for finding in self.labeler.self._security_hub.findings]
            ),
            ExportConfiguration(
                FILENAMES['labeled_accounts'],
                [account.data for account in self.labeler.labeled_accounts]
            )
        ]

    def print_to_console(self):
        print(
            f"The Landing Zone named {self.landing_zone_name} has a security score of: {self.labeler.energy_label_of_landing_zone}")


def is_s3_url(url):
    return urlparse.urlparse(url).scheme == "s3"


def is_directory_path(path):
    parsed_url = urlparse.urlparse(path)
    return parsed_url.scheme == "" and parsed_url.netloc == "" and len(parsed_url.path) >= 1


def main():
    parser = argparse.ArgumentParser(description='Reporting tool for AWS Security Hub')
    parser.add_argument('landingzone', type=str, help='The name of the Landing Zone.')
    parser.add_argument('--region', default='eu-west-1', type=str, required=False,
                        help='The AWS region, default is eu-west-1')
    parser.add_argument('--allow-list', metavar='AccountId', type=str, nargs='*',
                        help='A list of AWS Account IDs for which an energy label will be produced.')
    parser.add_argument('--deny-list', metavar='AccountId', type=str, nargs='*',
                        help='A list of AWS Account IDs that will be excluded from producing the energy label.')
    parser.add_argument('--export', default='', type=str, required=False,
                        help='Exports a snapshot of the reporting data in JSON formatted files to the specified directory or S3 location.')
    args = parser.parse_args()

    reporter = EnergyLabelReporter(args.landingzone, args.whitelist, args.blacklist)
    if args.export:
        if is_s3_url(args.export):
            reporter.export_as_json_to_s3(args.export)
        elif is_directory_path(args.export):
            reporter.export_as_json_to_fs(args.export)
        else:
            print("Invalid export path was given.")
            return 1
    reporter.print_to_console()
    return 0


if __name__ == '__main__':
    sys.exit(main())
