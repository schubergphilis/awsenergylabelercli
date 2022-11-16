#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: entities.py
#
# Copyright 2022 Costas Tyfoxylos
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
entities package.

Import all parts from entities here

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html
"""

import logging

from dataclasses import dataclass

__author__ = 'Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'
__docformat__ = '''google'''
__date__ = '''15-11-2022'''
__copyright__ = '''Copyright 2022, Costas Tyfoxylos'''
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

LOGGER_BASENAME = '''entities'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


@dataclass
class MetadataEntry:
    """Models a metadata entry."""

    title: str
    value: str
    is_report_entry: bool


class Metadata:
    """Models the metadata container that can parse the metadata entries."""

    def __init__(self):
        self._data = []

    def add_entry(self, entry):
        """Adds a metadata entry to the container.

        Args:
            entry: A metadata entry object.

        Returns:
            None

        """
        if not isinstance(entry, MetadataEntry):
            raise ValueError('Only MetadataEntry objects are allowed.')
        self._data.append(entry)

    @property
    def data(self):
        """The data of the included entries.

        Returns:
            The metadata entries in a dictionary.

        """
        return {entry.title: entry.value for entry in self._data}

    @property
    def report_table(self):
        """The data to be included in a report table.

        Returns:
            A list of entry data lists to be reported in an interactive report.

        """
        return [[entry.title, entry.value] for entry in self._data if entry.is_report_entry]
