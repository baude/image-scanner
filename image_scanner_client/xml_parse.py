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

'''Usefull functions to parse openscap oval xml files'''


import xml.etree.ElementTree as ET
from collections import namedtuple
from image_scanner_client import Client
from image_scanner_client import ImageScannerClientError
import urlparse
import json
import os


class ParseOvalXML(object):
    ''' Class that provides the functions '''

    _cve_tuple = namedtuple('oval_cve', ['title', 'severity', 'cve_ref_id',
                            'cve_ref_url', 'rhsa_ref_id', 'rhsa_ref_url',
                                         'cve', 'description'])

    result_list = []

    def __init__(self):
        self.local_basedir = None

    def _get_root(self, result_file):
        '''
        Returns an ET object for the input XML which can be a file
        or a URL pointing to an xml file
        '''
        if result_file.startswith("http://"):
            split_url = urlparse.urlsplit(result_file)
            image_scanner = Client(split_url.hostname, port=split_url.port)
            result_tree = image_scanner.getxml(result_file)
        else:
            result_tree = ET.parse(result_file)
        return result_tree.getroot()

    def _get_list_cve_def_ids(self, _root):
        '''Returns a list of cve definition ids in the result file'''
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
        '''
        Returns a list of tuples that contain information about the
        cve themselves.  Currently return are: title, severity, ref_id
        and ref_url for the cve and rhsa, the cve id, and description
        '''

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

    def get_cve_info(self, result_file):
        '''
        Wrapper function to return a list of tuples with
        cve information from the xml input file
        '''
        _root = self._get_root(result_file)
        _id_list = self._get_list_cve_def_ids(_root)
        return self._get_cve_def_info(_id_list, _root)

    def _get_docker_state(self, docker_state_file):
        '''
        Returns a JSON object provided the docker_state_file either
        as a URL or an XML file
        '''
        if docker_state_file.startswith("http://"):
            split_url = urlparse.urlsplit(docker_state_file)
            image_scanner = Client(split_url.hostname, port=split_url.port)
            result_json = image_scanner.get_docker_json(docker_state_file)
        else:
            result_json = json.loads(open(docker_state_file).read())
            self.local_basedir = os.path.basename(docker_state_file)
        return result_json

    def _summarize_docker_object(self, result_file, docker_json):
        '''
        takes a result.xml file and a docker state json file and
        compares output to give an analysis of a given scan
        '''

        summary = {'host': docker_json['host']}
        summary['scan_time'] = docker_json['scan_time']

        _root = self._get_root(result_file)

        host_name = _root.find("{http://oval.mitre.org/XMLSchema/"
                               "oval-results-5}results/"
                               "{http://oval.mitre.org/XMLSchema/"
                               "oval-results-5}system/"
                               "{http://oval.mitre.org/XMLSchema/"
                               "oval-system-characteristics-5}"
                               "oval_system_characteristics/"
                               "{http://oval.mitre.org/XMLSchema/"
                               "oval-system-characteristics-5}system_info/"
                               "{http://oval.mitre.org/XMLSchema/oval-system-"
                               "characteristics-5}primary_host_name")

        temp_array = host_name.text.split(":")
        item_id = temp_array[1]

        affected_image = 0
        affected_children = []
        is_image = self.is_id_an_image(docker_json, item_id)
        if is_image:
            affected_image = item_id
            for containers in docker_json['docker_state'][affected_image]:
                affected_children.append(containers['uuid'])
        else:
            for image_id in docker_json['docker_state']:
                for containers in docker_json['docker_state'][image_id]:
                    if item_id == containers['uuid']:
                        affected_image = image_id
            for containers in docker_json['docker_state'][affected_image]:
                affected_children.append(containers['uuid'])

        summary['image'] = affected_image
        summary['containers'] = affected_children

        scan_results = {}
        cve_format_list = self.get_cve_info(result_file)
        for cve in cve_format_list:
            if cve.severity not in scan_results:
                scan_results[cve.severity] = {'num': 1, 'cves': [cve.cve]}
            else:
                scan_results[cve.severity]['num'] += 1
                scan_results[cve.severity]['cves'].append(cve.cve)
        summary['scan_results'] = scan_results

        return summary

    def is_id_an_image(self, docker_json, item_id):
        '''
        helper function that uses the docker_state_file to validate if the
        given item_id is a container or image id
        '''

        for image_id in docker_json['docker_state']:
            if item_id == image_id:
                return True
            for containers in docker_json['docker_state'][image_id]:
                if item_id == containers['uuid']:
                    return False

        # Item was not found in the docker state file
        error_msg = 'The provided openscap xml result file was not generated' \
                    ' from the same run as the docker state file '
        raise ImageScannerClientError(error_msg)

    def print_summary(self, summary):
        '''
        given the input of the dict that is returned from the summerize def,
        this def will give a nice output to std out
        '''

        if summary['image'] is None or summary['containers'] is None:
            raise ImageScannerClientError("Summary data is not initialized")

        print "Time of Scan:"
        print "  " + summary['scan_time']
        print "Docker host:"
        print "  " + summary['image']
        print "Problematic image:"
        print "  " + summary['image']
        print "Affected containers: "
        for container in summary['containers']:
            print "  " + container
        print "Susceptible CVEs:"
        sev_list = {'Low', 'Moderate', 'Important', 'Critical'}
        for sev in sev_list:
            for key in summary['scan_results']:
                if key == sev:
                    print "  " + sev + ":"
                    print "    ",
                    print ', '.join(summary['scan_results'][sev]['cves'])

    def summary(self, docker_state_file):
        '''
        Takes a URL or file pointer to the docker_state_file. If
        the pointer is not http, it assumes that basedir of the
        point also contains all the xml files
        '''

        docker_state_obj = self._get_docker_state(docker_state_file)

        for scanned_obj in docker_state_obj['results_summary']:
            xml_url = scanned_obj[scanned_obj.keys()[0]]['xml_url']
            single_summary = self._summarize_docker_object(xml_url, docker_state_obj)
            self.print_summary(single_summary)
        
       
