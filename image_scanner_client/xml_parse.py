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


from image_scanner_client import Client
import urlparse
import json
import os
import sys


class ParseOvalXML(object):
    ''' Class that provides the functions '''

    BOLD = '\033[1m'
    END = '\033[0m'

    def __init__(self):
        self.local_reportdir = None
        self.containers = None
        self.images = None

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
            print error_msg
            sys.exit(1)

    def _fprint(self, indent, key, space_indent, val):
        ''' Pretty print helper function for formatting '''
        print "{0}{1}:\n{2}{3}".format(indent, self._wrap_bold(key),
                                       space_indent, val)

    @staticmethod
    def _get_base_image(docker_state_obj, cid):
        ''' Returns the base image for a container '''
        for image in docker_state_obj['docker_state']:
            for container in docker_state_obj['docker_state'][image]:
                if container['uuid'] == cid:
                    return image

    def _wrap_bold(self, value):
        ''' Wraps a string with bold ANSI markers '''
        return "{0}{1}{2}".format(self.BOLD, value, self.END)

    @staticmethod
    def _print_cve_info_by_sev(cve_obj):
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

    def pprint(self, docker_state_obj):
        '''
        Pretty print the output from a single host's image-scanner
        output.
        '''

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

    @staticmethod
    def debug_json(json_data):
        ''' Pretty prints a json object for debug purposes '''
        print json.dumps(json_data, indent=4, separators=(',', ': '))

    def return_rpm_by_docker_obj(self, docker_state_object):
        '''
        Given a docker_state_file this will return a dict with the rpms
        for all images in the docker_state_file. The return dict will have
        the format {image_id : [rpms]}, if the image is not rhel
        based, the rpms list will be empty
        '''
        rpm_dict = {}
        for i in docker_state_object['host_results']:
            rpm_dict[i] = []
            if not docker_state_object['host_results'][i]['isRHEL']:
                rpm_dict[i] = []
            else:
                rpm_dict[i] = docker_state_object['host_results'][i]['rpms']
        return rpm_dict

    @staticmethod
    def _walk_cves(scan_results):
        ''' Returns a dictionary of cves by severity'''
        cve_dict = {}
        for sev in scan_results:
            cve_dict[sev] = []
            for cve in scan_results[sev]['cves']:
                tmp_dict = {cve['cve']: {}}
                for key in cve.keys():
                    tmp_dict[cve['cve']][key] = cve[key]
                cve_dict[sev].append(tmp_dict)
        return cve_dict

    def return_cve_by_docker_obj(self, docker_state_object):
        ''' Returns a dictionary of cve information by scanned object'''
        scan_dict = {}
        for scanned_obj in docker_state_object['host_results']:
            fields = ['important', 'low', 'moderate', 'os', 'isRHEL',
                      'os', 'critical']
            scan_dict[scanned_obj] = {}
            dock_pointer = docker_state_object['host_results'][scanned_obj]
            dict_pointer = scan_dict[scanned_obj]
            for field in fields:
                dict_pointer[field] = dock_pointer[field] if field in \
                    dock_pointer else None

            # Using 1 line if looks weird, leaving this as is for now
            if 'cve_summary' in dock_pointer:
                cve_details = self._walk_cves(dock_pointer['cve_summary']
                                              ['scan_results'])
            else:
                cve_details = []

            dict_pointer['cves'] = cve_details

        return scan_dict
