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
    BOLD = '\033[1m'
    END = '\033[0m'

    def __init__(self):
        self.local_reportdir = None
        self.host_name = None
        self.containers = None
        self.images = None

    # FIXME
    # Deprecate
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

    # FIXME
    # Deprecate
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

    # FIXME
    # Deprecate
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

    # FIXME
    # Deprecate
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
            self.local_reportdir = os.path.dirname(docker_state_file)

        return result_json

    # Deprecate
    # FIXME
    def _return_cve_dict_info(self, result_file, title):
        '''
        Returns a dict containing the specific details of a cve which
        includes title, rhsa/cve ref_ids and urls, cve number, and
        description.
        '''

        cve_tuple = [cved for cved in self.cve_info if cved.title == title][0]
        cve_dict_info = {'cve_title': cve_tuple.title,
                         'cve_ref_id': cve_tuple.cve_ref_id,
                         'cve_ref_url': cve_tuple.cve_ref_url,
                         'rhsa_ref_id': cve_tuple.rhsa_ref_id,
                         'rhsa_ref_url': cve_tuple.rhsa_ref_url,
                         'cve': cve_tuple.cve
                         }

        return cve_dict_info

    # Deprecate
    # FIXME
    def _get_os_release(self, docker_obj, item_id):
        '''Simple function to grab the release for an item_id'''

        for result in docker_obj['results_summary']:
            if item_id in result:
                return result[item_id]['os'].rstrip()

    # Deprecate
    # FIXME
    def _summarize_docker_object(self, result_file, docker_json, item_id):
        '''
        takes a result.xml file and a docker state json file and
        compares output to give an analysis of a given scan
        '''

        self.cve_info = self.get_cve_info(result_file)

        affected_image = 0
        affected_children = []
        is_image = self.is_id_an_image(item_id, docker_json)

        summary = {}
        if is_image:
            summary['scanned_image'] = item_id
            affected_image = item_id
            affected_children = self._process_image(affected_image,
                                                    docker_json)
        else:
            summary['scanned_container'] = item_id
            affected_children, affected_image = \
                self._process_container(docker_json, item_id)

        summary['image'] = affected_image
        summary['containers'] = affected_children

        scan_results = {}
        for cve in self.cve_info:
            _cve_specifics = self._return_cve_dict_info(result_file,
                                                        cve.title)
            if cve.severity not in scan_results:
                scan_results[cve.severity] = \
                    {'num': 1,
                     'cves': [_cve_specifics]}
            else:
                scan_results[cve.severity]['num'] += 1
                scan_results[cve.severity]['cves'].append(_cve_specifics)
        summary['scan_results'] = scan_results
        # self.debug_json(summary)
        return summary

    def _process_container(self, docker_json, item_id):
        '''
        Returns containers with the same base image
        as a list
        '''
        affected_children = []
        for image_id in docker_json['docker_state']:
            for containers in docker_json['docker_state'][image_id]:
                if item_id == containers['uuid']:
                    base_image = image_id
        for containers in docker_json['docker_state'][base_image]:
            affected_children.append(containers['uuid'])

        return affected_children, base_image

    # Deprecate or rewrite
    def _process_image(self, affected_image, docker_json):
        '''
        Returns containers with a given base
        as a list
        '''
        affected_children = []
        # Catch an image that has no containers
        if affected_image not in docker_json['docker_state']:
            return []
        # It has children containers
        for containers in docker_json['docker_state'][affected_image]:
            affected_children.append(containers['uuid'])
        return affected_children

    def is_id_an_image(self, docker_id, docker_obj):
        '''
        helper function that uses the docker_state_file to validate if the
        given item_id is a container or image id
        '''

        if self.containers is None or self.images is None:
            self.containers = docker_obj['host_containers']
            self.images = docker_obj['host_images']

        if docker_id in self.images:
            return True
        elif docker_id in self.containers:
            return False
        else:
            # Item was not found in the docker state file
            error_msg = 'The provided openscap xml result file was ' \
                        'not generated from the same run as the ' \
                        'docker state file '
            raise ImageScannerClientError(error_msg)

    # Deprecate
    # FIXME
    def _iterate_severity(self, summary):
        sev_list = ['Critical', 'Important', 'Moderate', 'Low']
        for sev in sev_list:
            for key in summary['scan_results']:
                if key == sev:
                    print "{0}{1}({2}):" \
                        .format(" " * 2, sev,
                                summary['scan_results'][sev]['num'])
                    for cve in summary['scan_results'][sev]['cves']:
                        sev_gen = ("({0})".format(x) for x in sev_list)
                        replace_val = (g_val for g_index, g_val in
                                       enumerate(sev_gen) if g_val
                                       in cve['cve_title']).next()
                        print "{0}{1} {2}"\
                              .format(" " * 4, cve['cve_ref_id'],
                                      (cve['cve_title'].replace(replace_val,
                                                                ""))
                                      .split(':')[2].strip())
    # Deprecate
    # FIXME

    def print_summary(self, summary):
        '''
        given the input of the dict that is returned from the summerize def,
        this def will give a nice output to std out
        '''
        print "\n"

        # FIXME
        # What were you trying to catch here?
        # if summary['image'] is None or summary['containers'] is None:
        #     raise ImageScannerClientError("Summary data is not initialized")

        print "Time of Scan:\n{0}{1}".format(" " * 2, summary['scan_time'])
        print "Docker host:\n{0}{1}".format(" " * 2, summary['host'])

        if 'scanned_container' in summary:
            print "Scanned container:\n{0}{1}"\
                  .format(" " * 2, summary['scanned_container'])
        else:
            print "Scanned image:\n{0}{1}"\
                  .format(" " * 2, summary['scanned_image'])

        print "Base image:\n{0}{1}".format(" " * 2, summary['image'])
        print "RHEL release:\n{0}{1}".format(" " * 2, summary['os'])
        print "Containers based on same image: "
        if len(summary['containers']) > 0:
            for container in summary['containers']:
                print "{0}{1}".format(" " * 2, container)
        # If there are no children containers
        # then print None
        else:
            print "{0}{1}".format(" " * 2, "None")

        print "Susceptible CVEs:"
        if len(summary['scan_results'].keys()) > 0:
            self._iterate_severity(summary)
        else:
            print "{0}None".format(" " * 2)

    # I think this should be deprecated
    def _print_non_RHEL(self, docker_state_obj, docker_id):
        my_obj = "image"
        print "\n"
        print "Time of scan:\n{0}{1}".format(" " * 2,
                                             docker_state_obj['scan_time'])
        print "Docker host:\n{0}{1}".format(" " * 2, docker_state_obj['host'])
        if not self.is_id_an_image(docker_state_obj, docker_id):
            my_obj = "container"
        print "Scanned {0} (Not RHEL-based, no scan performed):\n{1}{2}"\
              .format(my_obj, " " * 2, docker_id)

    def _fprint(self, indent, key, space_indent, val):
        ''' Pretty print helper function for formatting '''
        print "{0}{1}:\n{2}{3}".format(indent, self._wrap_bold(key),
                                       space_indent, val)

    def _get_base_image(self, docker_state_obj, cid):
        ''' Returns the base image for a container '''
        for image in docker_state_obj['docker_state']:
            for container in docker_state_obj['docker_state'][image]:
                if container['uuid'] == cid:
                    return image

    def _wrap_bold(self, value):
        ''' Wraps a string with bold ANSI markers '''
        return "{0}{1}{2}".format(self.BOLD, value, self.END)

    def _print_cve_info_by_sev(self, cve_obj):
        '''
        Helper function to print out cve information
        '''
        seven = " " * 7
        ten = " " * 10

        sev_list = ['Critical', 'Important', 'Moderate', 'Low']
        cve_keys = cve_obj.keys()
        for sev in sev_list:
            if sev in cve_keys:
                tmp_cve = cve_obj[sev]
                print "{0}{1} ({2}):".format(seven, sev, tmp_cve['num'])
                for cve in tmp_cve['cves']:
                    sev_gen = ("({0})".format(x) for x in sev_list)
                    replace_val = (g_val for g_index, g_val in
                                   enumerate(sev_gen) if g_val in
                                   cve['cve_title']).next()
                    print "{0}{1}{2}".\
                          format(ten, cve['cve_ref_id'],
                                 cve['cve_title'].replace(replace_val, "").
                                 split(':')[2].rstrip())

    def pprint(self, docker_state_file):
        '''
        Pretty print the output from a single host's image-scanner
        output.
        '''
        docker_state_obj = self._get_docker_state(docker_state_file)
        two = " " * 2
        five = " " * 5
        seven = " " * 7

        print "\n"
        self._fprint("", 'Host', two, docker_state_obj['hostname'])
        self._fprint(two, 'Scan Time', five, docker_state_obj['scan_time'])

        for scanned_obj in docker_state_obj['host_results']:
            print "\n"
            tmp_obj = docker_state_obj['host_results'][scanned_obj]
            scan_type = 'image' if self.is_id_an_image(scanned_obj, docker_state_obj) \
                else 'container'
            self._fprint(two, 'Scanned ' + scan_type, five, scanned_obj + "\n")
            if not tmp_obj['isRHEL']:
                # The OS is not RHEL, so skip to next item in the for loop
                self._fprint(five, 'OS', seven, "Not RHEL")
                continue
            self._fprint(five, "OS", seven, tmp_obj['os'].rstrip())
            if scan_type is 'container':
                base_image = self._get_base_image(docker_state_obj,
                                                  scanned_obj)
                self._fprint(five, "Base Image", seven, base_image)

            print "{0}{1}:".format(five,
                                   self._wrap_bold('Containers based '
                                                   'on same image'))
            if len(tmp_obj['cve_summary']['containers']) > 0:
                for container in tmp_obj['cve_summary']['containers']:
                    print "{0}{1}".format(seven, container)
            else:
                print "{0}{1}".format(seven, 'None')

            if len(tmp_obj['cve_summary']['scan_results'].keys()) > 0:
                print "{0}{1}:".format(five, self._wrap_bold('CVEs found'))
                self._print_cve_info_by_sev(
                    tmp_obj['cve_summary']['scan_results'])

    # I think this should be deprecated
    def summary(self, docker_state_file, pprint=False, pprint_summary=False):
        '''
        Takes a URL or file pointer to the docker_state_file. If
        the pointer is not http, it assumes that reportdir of the
        point also contains all the xml files
        '''
        for scanned_obj in docker_state_obj['host_results']:
            tmp_obj = docker_state_obj['host_results'][scanned_obj]
            print tmp_obj['os']

    def debug_json(self, json_data):
        ''' Pretty prints a json object for debug purposes '''
        print json.dumps(json_data, indent=4, separators=(',', ': '))

    def _get_rpms(self, docker_state_file):
        '''
        Given a docker_state_file this will return a dict with the rpms
        for all images in the docker_state_file. The return dict will have
        the format {image_id : [rpms]}, if the image is not rhel 
        based, the rpms list will be empty
        '''
        docker_state = self._get_docker_state(docker_state_file)
        rpm_dict = {}
        for i in docker_state['host_results']:
            rpm_dict[i] = []
            if not docker_state['host_results'][i]['isRHEL']:
                rpm_dict[i] = []
            else:
                rpm_dict[i] = docker_state['host_results'][i]['rpms']
        return rpm_dict
