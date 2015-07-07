#!/usr/bin/env python

# Import the client
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

from image_scanner_client import Client
from xml_parse import ParseOvalXML
import json

debug = True


def debug_print(json_data):
    ''' Simple helper function to pretty-print JSON data '''
    print json.dumps(json_data, indent=4, separators=(',', ': '))

xmlp = ParseOvalXML()

# Create the connection to the host
image_scanner = Client("localhost", "5001", "4")

# Scan an image or container
# scan_results = image_scanner.scan_list(['bef54'])
scan_results = image_scanner.scan_list(['c0bb'])

# The result of scan_list will return a JSON based structure
# that has a very basic summary of the scan as well as
# information you can use to get more granular information
# about the scan results

if debug:
    debug_print(scan_results)

# To get more granular information on the results, grab the
# resulting docker_state.json file from scan_results which is
# also a JSON structure.

docker_state = image_scanner.get_docker_json(scan_results['json_url'])

if debug:
    debug_print(docker_state)

# The docker_state is the core of source of information regarding
# the results of the previous scan. We can now use various functions
# inside the xmlp object to extract specific information

# List of RPMS per scanned ID
rpm_dict = xmlp.return_rpm_by_docker_obj(docker_state)

if debug:
    debug_print(rpm_dict)

# List of cve information per scanned ID
cve_list = xmlp.return_cve_by_docker_obj(docker_state)

if debug:
    debug_print(cve_list)

# If you prefer to just get a summarized print out of the scan with
# details, you can also simply use the pprint function

xmlp.pprint(docker_state)

# Check out the README on https://github.com/baude/image-scanner
# for more information.
