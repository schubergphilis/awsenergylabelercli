import argparse
from ExportSecurityHubData import EnergyLabeler
import os
import tempfile
import boto3
from urllib.parse import urlparse
from urllib.parse import urljoin
import os.path


FILENAMES = {
    energy_label: "energylabel-of-landingzone.json",
    findings: "securityhub-findings.json",
    labeled_accounts: "labeled-accounts.json"
}

@dataclass
class ExportConfiguration:
    filename: str
    data: []

class SecurityHubReporter:

    def __init__(self, landing_zone_name, whitelist, blacklist):
        self.landing_zone_name = landing_zone_name
        self.whitelist = whitelist
        self.blacklist = blacklist
        self.labeler = EnergyLabeler(landing_zone_name)

        self.export_configurations = [
            ExportConfiguration(FILENAMES['energy_label'],
                [{'Landing Zone': self.landing_zone_name, 'Landing Zone Energy Label': self.labeler.energy_label_of_landing_zone}]
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
        print(f"The Landing Zone named {self.landing_zone_name} has a security score of: {self.labeler.energy_label_of_landing_zone}")

    def export_as_json_to_fs(self, directory):
        if(not(path.exists(directory))):
           os.makedirs(directory)
        for entry in self.export_configurations:
            filepath = os.path.join(directory, entry.filename)
            with open(filepath, 'w') as jsonfile:
                json.dump(entry.data, jsonfile, indent=2, default=str)

    def export_as_json_to_s3(self, s3_url):
        s3 = boto3.client('s3')
        parsed_url = urlparse.urlparse(s3_url)
        bucket_name=parsed_url.netloc
        dst_path = parsed_url.path

        for entry in self.export_configurations:
            with tempfile.NamedTemporaryFile() as temp_file:
                temp_file.write(entry.data)
                temp_file.flush()
                dst_filename = urljoin(dst_path, entry.filename)
                s3.upload_file(temp_file.name, bucket_name, dst_filename)
                temp_file.close()


def is_s3_url(url):
    return urlparse.urlparse(url).scheme == "s3"

def is_directory_path(path):
    parsed_url = urlparse.urlparse(url)
    return parsed_url.scheme == "" and parsed_url.netloc=="" and len(parsed_url.path) >= 1

def main():
    parser = argparse.ArgumentParser(description='Reporting tool for AWS Security Hub')
    parser.add_argument('landingzone', type=str, help='The name of the Landing Zone.')
    parser.add_argument('--region', default='eu-west-1', type=str, required=False,
                         help='The AWS region, default is eu-west-1')
    parser.add_argument('--whitelist', metavar='AccountId', type=str, nargs='*',
                         help='A list of AWS Account IDs for which an energy label will be produced.')
    parser.add_argument('--blacklist', metavar='AccountId', type=str, nargs='*',
                         help='A list of AWS Account IDs that will be excluded from producing the energy label.')
    parser.add_argument('--export', default='', type=str, required=False,
                         help='Exports a snapshot of the reporting data in JSON formatted files to the specified directory or S3 location.')
    args = parser.parse_args()

    reporter = SecurityHubReporter(args.landingzone, args.whitelist, args.blacklist)
    if(args.export):
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

