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

''' Image Scanner remote client for command line '''
from image_scanner_client.image_scanner_client import Client, ImageScannerClientError, ClientCommon
from image_scanner_client.xml_parse import ParseOvalXML
import sys
import argparse
import os


class RemoteScanner(object):

    ''' Class that prepares user inputs and then calls the scan'''

    config_file = "/etc/image-scanner/image-scanner-client.conf"

    def __init__(self, parseargs):
        ''' Simple init with config parsing '''

        if not os.path.exists(self.config_file):
            print "Unable to find config file at " \
                  "{0}".format(self.config_file)

        self.args = parseargs
        client_common = ClientCommon()
        try:
            host, port, number, cert = \
                client_common.get_profile_info(parseargs.profile)
        except ImageScannerClientError as common_error:
            print common_error
            sys.exit(1)
        number = parseargs.number
        self.remote_client = Client(host, port, number)
        self.xmlp = ParseOvalXML()
        self.ping_host = None

    def scan(self):
        ''' Executes the scan on the remote host'''
        try:
            if self.args.allprofiles:
                multi_scan = ClientCommon(api=False)
                profiles = multi_scan.return_all_profiles()

                # Check to make sure REST and docker are
                # running on each host

                for profile in profiles:
                    self.ping_host = profile.host
                    ping_check = Client(profile.host, profile.port)
                    ping_check.ping()

                profile_list = [profile.profile for profile in profiles]
                results = multi_scan.\
                    scan_multiple_hosts(profile_list, self.args)
                return results

            if self.args.onlyactive:
                return self.remote_client.scan_all_containers(onlyactive=True)

            if self.args.allcontainers:
                return self.remote_client.scan_all_containers()

            if self.args.scan:
                return self.remote_client.scan_list(self.args.scan)

            if self.args.allimages:
                return self.remote_client.scan_images(all=True)

            if self.args.images:
                return self.remote_client.scan_images(all=False)

        except ImageScannerClientError as remote_error:
            print remote_error
            sys.exit(1)

    def _get_docker_state(self, summary):
        ''' Returns the docker-state_file using the summary as input '''
        docker_state = self.remote_client.get_docker_json(summary['json_url'])
        return docker_state

    def print_results(self, json_url):
        ''' Pretty print call to dump results'''
        self.xmlp.pprint(json_url)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Scan Utility for Containers')
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument('--images', help='search images', default=False,
                       action='store_true')
    group.add_argument('--allimages', help='search all images', default=False,
                       action='store_true')
    group.add_argument('--onlyactive', help='search only active containers',
                       default=False, action='store_true')
    group.add_argument('--allcontainers', help='search all containers',
                       default=False, action='store_true')
    group.add_argument('-s', '--scan', help='image to search',
                       action='append')
    parser.add_argument('-n', '--number', help='number of processors to use',
                        type=int, default=2)

    parser.add_argument('--port', help='Port for the image-scanner-d',
                        type=int, default=5001)
    parser.add_argument('--host', help='Host name or IP of the '
                        'image-scanner-d', default=None)
    parser.add_argument('-r', '--remote_threads', help='The number of remote '
                        'hosts to scan simultaneously', default=4)

    profile = parser.add_mutually_exclusive_group()

    profile.add_argument('--profile', help='Profile from configuration file',
                         default='localhost')
    profile.add_argument('--allprofiles',
                         help='Run the scanner on all profiles',
                         default=False, action='store_true')

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    remotescan = RemoteScanner(args)
    scansummary = remotescan.scan()
    if not args.allprofiles:
        remotescan.print_results(scansummary['json_url'])
    else:
        common = ClientCommon()
        common.mult_host_mini_pprint(scansummary)
