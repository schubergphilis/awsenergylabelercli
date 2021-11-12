#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: helpers.py
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
helpers package.

Import all parts from helpers here

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html
"""

import json
import logging
import os
import os.path
import tempfile

from urllib.parse import urljoin, urlparse

import boto3

from awsenergylabelercli.awsenergylabelercliexceptions import InvalidPath

__author__ = '''Theodoor Scholte <tscholte@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''11-11-2021'''
__copyright__ = '''Copyright 2021, Theodoor Scholte'''
__license__ = '''MIT'''
__maintainer__ = '''Theodoor Scholte'''
__email__ = '''<tscholte@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


# This is the main prefix used for logging
LOGGER_BASENAME = '''helpers'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


class DestinationPath:

    def __init__(self, location):
        self.location = location
        self._parsed_url = urlparse(location)
        self._s3_conditions = [self._parsed_url.scheme == "s3", len(self._parsed_url.path) >= 1]
        self._local_conditions = [self._parsed_url.scheme == "",
                                  self._parsed_url.netloc == "",
                                  len(self._parsed_url.path) >= 1]

    def is_valid(self):
        return all(self._s3_conditions or self._local_conditions)

    @property
    def type(self):
        if all(self._s3_conditions):
            return 's3'
        if all(self._local_conditions):
            return 'local'
        raise InvalidPath(self.location)


class DataFile:  # pylint: disable=too-few-public-methods
    """Data export factory to handle the different data types returned."""

    def __new__(cls, data_type, labeler):
        if data_type == 'energy_label':
            obj = EnergyLabelingData('energylabel-of-landingzone.json', labeler)
        elif data_type == 'findings':
            obj = SecurityHubFindingsData('securityhub-findings.json', labeler)
        elif data_type == 'labeled_accounts':
            obj = LabeledAccountsData('labeled-accounts.json', labeler)
        else:
            LOGGER.error('Unknown data type %s', data_type)
            return None
        return obj


class EnergyLabelingData:
    """Models the data for energy labeling to export."""

    def __init__(self, filename, labeler):
        self.filename = filename
        self._labeler = labeler

    @property
    def json(self):
        return json.dumps([{'Landing Zone Name': self._labeler.landing_zone_name,
                            'Landing Zone Energy Label': self._labeler.energy_label_of_landing_zone}],
                          indent=2, default=str)


class SecurityHubFindingsData:
    """Models the data for energy labeling to export."""

    def __init__(self, filename, labeler):
        self.filename = filename
        self._labeler = labeler

    @property
    def json(self):
        return json.dumps(self._labeler.security_hub_findings_data, indent=2, default=str)


class LabeledAccountsData:
    """Models the data for energy labeling to export."""

    def __init__(self, filename, labeler):
        self.filename = filename
        self._labeler = labeler

    @property
    def json(self):
        return json.dumps([{'Account ID': account.id,
                            'Account Name': account.name,
                            'Energy Label': account.energy_label}
                           for account in self._labeler.labeled_accounts], indent=2, default=str)


class DataExporter:
    """Export AWS security data."""

    def __init__(self, energy_labeler):
        self.energy_labeler = energy_labeler
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')

    def export(self, path):
        destination = DestinationPath(path)
        if not destination.is_valid():
            raise InvalidPath(path)
        export = self._export_to_s3 if destination.type == 's3' else self._export_to_fs
        for file_type in ['energy_label', 'findings', 'labeled_accounts']:
            data_file = DataFile(file_type, self.energy_labeler)
            export(path, data_file.filename, data_file.json)

    def _export_to_fs(self, directory, filename, data):
        """Exports as json to local filesystem."""
        if not os.path.exists(directory):
            os.makedirs(directory)
        filepath = os.path.join(directory, filename)
        with open(filepath, 'w') as jsonfile:
            jsonfile.write(data)
        self._logger.debug(f'File {filename} copied to {directory}')

    def _export_to_s3(self, s3_url, filename, data):
        """Exports as json to S3 object storage."""
        s3 = boto3.client('s3')  # pylint: disable=invalid-name
        parsed_url = urlparse(s3_url)
        bucket_name = parsed_url.netloc
        dst_path = parsed_url.path
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(data)
            temp_file.flush()
            dst_filename = urljoin(dst_path, filename)
            s3.upload_file(temp_file.name, bucket_name, dst_filename)
            temp_file.close()
        self._logger.debug(f'File {filename} copied to {s3_url}')

