#!/usr/bin/env python
# Copyright (C) 2015 Brent Baude <bbaude@redhat.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the
# Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.

''' Usefull functions to parse openscap oval xml files'''


import xml.etree.ElementTree as ET
from collections import namedtuple


class ParseOvalXML(object):
    ''' Class that provides the functions '''

    _cve_tuple = namedtuple('oval_cve', ['title', 'severity', 'cve_ref_id',
                            'cve_ref_url', 'rhsa_ref_id', 'rhsa_ref_url',
                                         'cve', 'description'])

    result_list = []

    def _get_root(self, result_file):
        result_tree = ET.parse(result_file)
        return result_tree.getroot()

    def _get_list_cve_def_ids(self, _root):
        _def_id_list = []
        definitions = _root.findall("{http://oval.mitre.org/XMLSchema/"
                                    "oval-results-5}results/{http://oval.mitre"
                                    ".org/XMLSchema/oval-results-5}system/{"
                                    "http://oval.mitre.org/XMLSchema/oval-"
                                    "results-5}definitions/*[@result='true']")
        for def_id in definitions:
            _def_id_list.append(def_id.attrib['definition_id'])

        return _def_id_list

    def _get_cve_def_info(self, _def_id_list, _root):
        cve_info_list = []
        for def_id in _def_id_list:
            oval_defs = _root.find("{http://oval.mitre.org/XMLSchema/oval-"
                                   "definitions-5}oval_definitions/{http://"
                                   "oval.mitre.org/XMLSchema/oval-definitions-"
                                   "5}definitions/*[@id='%s']/{http://oval."
                                   "mitre.org/XMLSchema/oval-definitions-5}"
                                   "metadata" % def_id)
            # title
            title = oval_defs.find("{http://oval.mitre.org/XMLSchema/oval-"
                                   "definitions-5}title").text
            rhsa_meta = oval_defs.find("{http://oval.mitre.org/XMLSchema/oval"
                                       "-definitions-5}reference[@source="
                                       "'RHSA']")
            cve_meta = oval_defs.find("{http://oval.mitre.org/XMLSchema/oval-"
                                      "definitions-5}reference[@source='CVE']")
            # description
            description = oval_defs.find("{http://oval.mitre.org/XMLSchema/"
                                         "oval-definitions-5}description").text
            # severity
            severity = oval_defs.find("{http://oval.mitre.org/XMLSchema/oval-"
                                      "definitions-5}advisory/{http://oval."
                                      "mitre.org/XMLSchema/oval-definitions"
                                      "-5}severity").text
            cve_info_list.append(
                self._cve_tuple(title=title, severity=severity,
                                cve_ref_id=None if cve_meta is None
                                else cve_meta.attrib['ref_id'],
                                cve_ref_url=None if cve_meta is None
                                else cve_meta.attrib['ref_url'],
                                rhsa_ref_id=rhsa_meta.attrib['ref_id'],
                                rhsa_ref_url=rhsa_meta.attrib['ref_url'],
                                cve=def_id.replace(
                                    "oval:com.redhat.rhsa:def:", ""),
                                description=description))

        return cve_info_list

    def summarize(self, cve_format_list):
        summary = {}
        for cve in cve_format_list:
            if cve.severity not in summary:
                summary[cve.severity] = {'num': 1, 'cves': [cve.cve]}
            else:
                summary[cve.severity]['num'] += 1
                summary[cve.severity]['cves'].append([cve.cve])

# FIXME
# Would be nice to have the tuple or a summary function
# that also associates things with docker information. For 
# example, if the source was an image, list all the possible
# impacted container IDs.


