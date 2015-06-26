#!/usr/bin/env python

# Import the client
from image_scanner_client import Client
from xml_parse import ParseOvalXML
import json
xmlp = ParseOvalXML()
# Create the connection to the host
image_scanner = Client("localhost", "5001", "4")

# Scan an image or container
scan_results = image_scanner.scan_list(['1eb5214dc02d'])
# scan_results = image_scanner.scan_all_containers()

# docker_state = image_scanner.get_docker_json(scan_results['json_url'])

port = scan_results['port']
host = scan_results['host']

xmlp.summary(scan_results['json_url'])

# Need to iterate the results
# for result in scan_results['results']:
#     docker_id = result.keys()[0]
#     cve_info = xmlp.get_cve_info(result[docker_id]['xml_url'])
#     summary = xmlp.summarize(result[docker_id]['xml_url'],
#                              scan_results['json_url'])
#     xmlp.print_summary(summary)
