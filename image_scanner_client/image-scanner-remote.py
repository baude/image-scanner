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
from image_scanner_client import Client, ImageScannerClientError
from xml_parse import ParseOvalXML
import sys
import ConfigParser
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
        host, port = self.get_profile_info(parseargs.profile)
        number = parseargs.number
        self.remote_client = Client(host, port, number)
        self.xmlp = ParseOvalXML()

    def scan(self):
        ''' Executes the scan on the remote host'''
        try:
            if self.args.onlyactive:
                self.remote_client.scan_all_containers(onlyactive=True)

            if self.args.allcontainers:
                return self.remote_client.scan_all_containers()

            if self.args.images:
                return self.remote_client.scan_list(args.images)

        except ImageScannerClientError as remote_error:
            print remote_error
            sys.exit(1)

    def get_profile_info(self, profile):
        ''' Looks for host and port based on the profile provided '''

        config = ConfigParser.RawConfigParser()
        config.read(self.config_file)
        try:
            port = config.get(profile, 'port')
            host = config.get(profile, 'host')
        except ConfigParser.NoSectionError:
            print "The profile {0} cannot be found " \
                  "in {1}".format(profile, self.config_file)
            sys.exit(1)
        except ConfigParser.NoOptionError as no_option:
            print "No option {0} found in profile "\
                  "{1} in {2}".format(no_option.option,
                                      profile,
                                      self.config_file)
            sys.exit(1)
        return host, port

    def _get_docker_state(self, summary):
        docker_state = self.remote_client.get_docker_json(summary['json_url'])
        return docker_state

    def print_results(self, docker_state):
        self.xmlp.summary(docker_state)
        #for scanned_obj in docker_state['results_summary']:
        #    xml_url = scanned_obj[scanned_obj.keys()[0]]['xml_url']
        #    xml_et = self.remote_client.getxml(xml_url)
        #    print self.xmlp.summarize(xml_et, docker_state)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Scan Utility for Containers')
    group = parser.add_mutually_exclusive_group()

    group.add_argument('--allimages', help='search all images', default=False,
                       action='store_true')
    group.add_argument('--onlyactive', help='search only active containers',
                       default=False, action='store_true')
    group.add_argument('--allcontainers', help='search all containers',
                       default=False, action='store_true')
    group.add_argument('-i', '--images', help='image to search',
                       action='append')
    parser.add_argument('-n', '--number', help='number of processors to use',
                        type=int, default=2)

    parser.add_argument('--port', help='Port for the image-scanner-d',
                        type=int, default=5001)
    parser.add_argument('--host', help='Host name or IP of the '
                        'image-scanner-d', default=None)

    parser.add_argument('--profile', help='Profile from configuration file',
                        default='localhost')
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    remotescan = RemoteScanner(args)
    scansummary = remotescan.scan()
    docker_state = remotescan._get_docker_state(scansummary)
    remotescan.print_results(scansummary['json_url'])
