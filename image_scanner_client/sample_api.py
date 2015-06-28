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
scan_results = image_scanner.scan_list(['bef54'])

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

# We can now "walk" the results information in docker_state
# to get more information using the APIs in xml_parse. The
# _summarize_docker_object function simply needs a pointer
# to the openscal OVAL XML result file and the docker_state
# object we obtained above.


for result in scan_results['results']:
    # docker_id will be the id of the container or image
    # that was scanned.
    docker_id = result.keys()[0]
    result_json = xmlp._summarize_docker_object(result[docker_id]['xml_url'],
                                                docker_state)

    # The result_json object will be a JSON structure
    # with a lot of granular information about the scan
    # and the CVEs that were found.
    if debug:
        debug_print(result_json)


# If you prefer to just get a print out of the scan with
# details, you can also simply use the summary function
# in xml_parse which only needs a pointer to the the
# docker_state.json file.

xmlp.summary(scan_results['json_url'])

# Check out the README on https://github.com/baude/image-scanner
# for more information.
