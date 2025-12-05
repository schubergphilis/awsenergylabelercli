#!/usr/bin/env python
# File: _version.py
#
# Copyright 2021 Theodoor Scholte, Costas Tyfoxylos, Jenda Brands
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
Manages the version of the package.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

from pathlib import Path

__author__ = """Theodoor Scholte <tscholte@schubergphilis.com>"""
__docformat__ = """google"""
__date__ = """11-11-2021"""
__copyright__ = """Copyright 2021, Theodoor Scholte"""
__license__ = """MIT"""
__maintainer__ = """Theodoor Scholte"""
__email__ = """<tscholte@schubergphilis.com>"""
__status__ = """Development"""  # "Prototype", "Development", "Production".

VERSION_FILE_PATH = Path(__file__).parent.parent / ".VERSION"

LOCAL_VERSION_FILE_PATH = Path(__file__).parent / ".VERSION"

try:
    __version__ = VERSION_FILE_PATH.read_text(encoding="utf-8")
except OSError:
    __version__ = LOCAL_VERSION_FILE_PATH.read_text(encoding="utf-8")
