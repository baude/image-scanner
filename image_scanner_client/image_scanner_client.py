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

''' Image scanner API '''

import requests
import urlparse
import json
import xml.etree.ElementTree as ET


class ImageScannerClientError(Exception):
    """Docker Error"""
    pass


class Client(requests.Session):
    ''' The image-scanner client API '''
    request_headers = {'content-type': 'application/json'}

    def __init__(self, host, port=5001, number=2):
        '''
        When instantiating, pass in the host and optionally
        the port and threading counts
        '''
        super(Client, self).__init__()
        self.host = "http://{0}:{1}" .format(host, port)
        self.api_path = "image-scanner/api"
        self.num_threads = number

    def scan_all_containers(self, onlyactive=False):
        ''' Scans all containers and returns results in json'''
        url = urlparse.urljoin(self.host, self.api_path + "/scan")
        con_scan = 'allcontainers' if onlyactive is False else 'onlyactive'
        params = {con_scan: True, 'number': self.num_threads}
        results = self._get_results(url, data=json.dumps(params))
        return json.loads(results.text)

    def scan_list(self, scan_list):
        '''
        Scans a list of containers/images by name or id and returns
        results in json
        '''
        if not isinstance(scan_list, list):
            raise ImageScannerClientError("You must pass input in list form")
        url = urlparse.urljoin(self.host, self.api_path + "/scan")
        params = {'images': scan_list, 'number': self.num_threads}
        results = self._get_results(url, data=json.dumps(params))
        return json.loads(results.text)

    def scan_all_images(self):
        '''Scans all images and returns results in json'''
        url = urlparse.urljoin(self.host, self.api_path + "/scan")
        params = {'allimages': True, 'number': self.num_threads}
        results = self._get_results(url, data=json.dumps(params))
        return json.loads(results.text)

    def inspect_container(self, cid):
        '''Inspects a container and returns all results in json'''
        url = urlparse.urljoin(self.host, self.api_path + "/inspect_container")
        results = self._get_results(url, data=json.dumps({'cid': cid}))
        return json.loads(results.text)

    def inspect_image(self, iid):
        '''Inspects a container and returns the results in json'''
        url = urlparse.urljoin(self.host, self.api_path + "/inspect_image")
        results = self._get_results(url, json.dumps({'iid': iid}))
        return json.loads(results.text)

    def getxml(self, url):
        '''
        Given a URL string, returns the results of an openscap XML file as
        an Element Tree
        '''
        results = self.get(url)

        return ET.ElementTree(ET.fromstring(results.content))

    def get_docker_json(self, url):
        '''
        Given a URL, return the state of the docker containers and images
        when the images-scanning occurred.  Returns as JSON object.
        '''
        results = self.get(url)
        return json.loads(results.text)

    def _get_results(self, url, data, headers=None):
        '''Wrapper functoin for calling the request.session.get'''
        headers = self.request_headers if headers is None else headers
        return self.get(url, data=data, headers=headers)
