#!/usr/bin/env python

# Import the client
from image_scanner_client import Client
from xml_parse import ParseOvalXML

xmlp = ParseOvalXML()
# Create the connection to the host
image_scanner = Client("localhost", "5001", "4")

# Scan an image or container
scan_results = image_scanner.scan_list(['bef54', '10acc'])

#docker_state = image_scanner.get_docker_json(scan_results['json_url'])


port = scan_results['port']
host = scan_results['host']

# Need to iterate the results
for result in scan_results['results']:
    docker_id = result.keys()[0]
    print result[docker_id]['xml_url']
    #print xmlp._get_root(result[docker_id]['xml_url'])
    cve_info = xmlp.get_cve_info(result[docker_id]['xml_url'])

    print xmlp.summarize(cve_info, scan_results['json_url'])
# Test ET


