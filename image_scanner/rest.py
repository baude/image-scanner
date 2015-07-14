# !/usr/bin/env python
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

'''Rest API server side for image-scanner'''

import flask
import os
import collections
from flask import jsonify, request, send_from_directory
# from flask import make_response
from image_scanner.docker_scanner import Worker
import docker
import argparse
import sys
import ConfigParser
from image_scanner_client.image_scanner_client import ImageScannerClientError
import requests

application = flask.Flask(__name__, static_path='/var/tmp/image-scanner/')
# app.config.update(SERVER_NAME='127.0.0.1:5001')

scan_args = ['allcontainers', 'allimages', 'images', 'logfile', 'nocache',
             'number', 'onlyactive', 'reportdir',
             'workdir', 'api', 'url_root', 'host', 'rest_host', 'rest_port',
             'scan']

scan_tuple = collections.namedtuple('Namespace', scan_args)

rest_path = '/image-scanner/api/'

docker_host = "unix://var/run/docker.sock"
connection = docker.Client(base_url=docker_host, timeout=10)
port = None


def create_tuple(in_args, url_root, rest_host, rest_port):
    ''' Creates a tuple as input for the tuple class'''
    global scan_args
    global scan_tuple
    global docker_host
    _tmp_tuple = scan_tuple(allcontainers=False if
                            in_args.get('allcontainers') is None else
                            in_args.get('allcontainers'),
                            allimages=False if in_args.get('allimages') is
                            None else in_args.get('allimages'),
                            images=False if in_args.get('images') is
                            None else in_args.get('images'),
                            scan=in_args.get('scan') if
                            in_args.get('scan') is not None else None,
                            logfile="/var/tmp/image-scanner/openscap.log" if
                            in_args.get('logfile') is None else
                            in_args.get('logile'),
                            nocache=False if in_args.get('nocache') is None
                            else in_args.get('nocache'),
                            number=2 if in_args.get('number') is None else
                            int(in_args.get('number')),
                            onlyactive=False if in_args.get('onlyactive') is
                            None else in_args.get('onlyactive'),
                            reportdir="/var/tmp/image-scanner/" if
                            in_args.get('reportdir') is
                            None else in_args.get('reportdir'),
                            workdir="/var/tmp/image-scanner" if
                            in_args.get('workdir') is None
                            else in_args.get('workdir'),
                            api=True,
                            url_root=url_root,
                            host=docker_host,
                            rest_port=rest_port,
                            rest_host=rest_host)
    return _tmp_tuple


@application.route(os.path.join(rest_path, "test"), methods=['GET'])
def hello_world():
    ''' Test method'''
    return "hello"


@application.route(os.path.join(rest_path, "containers"), methods=['GET'])
def containers():
    '''Returns all containers'''
    global connection
    cons = {'all_containers': connection.containers(all=True)}
    return jsonify(cons)


@application.route(os.path.join(rest_path, "images"), methods=['GET'])
def images():
    '''Returns all images'''
    global connection
    images = {'all_images': connection.images(all=True)}
    return jsonify(images)


@application.route(os.path.join(rest_path, "inspect_container"),
                   methods=['GET'])
def inspect_container():
    ''' Returns inspect data of a container'''
    global connection
    inspect_data = connection.inspect_container(request.json['cid'])
    return jsonify(inspect_data)


@application.route(os.path.join(rest_path, "inspect_image"), methods=['GET'])
def inspect_image():
    ''' Returns inspect data of an image'''
    global connection
    inspect_data = connection.inspect_image(request.json['iid'])
    return jsonify(inspect_data)


@application.route(os.path.join(rest_path, "ping"), methods=['GET'])
def ping():
    ''' Returns true if the docker host is alive '''
    global connection
    try:
        connection.ping()
        return jsonify({'results': True})
    except requests.exceptions.ConnectionError:
        return jsonify({'Error': 'Docker on the host does not appear '
                        'to be running'})


@application.route(os.path.join(rest_path, "scan"), methods=['GET','POST'])
def scan():
    ''' Kicks off a scan via REST '''
    try:
        port, host, dockerhost = get_env_info()
    except ConfigParser.NoSectionError:
        return jsonify({'Error': 'Unable to parse conf file'})
    arg_tup = create_tuple(request.json, request.url_root, host, port)

    try:
        worker = Worker(arg_tup)
    except ImageScannerClientError:
        return jsonify({'Error': "Failed to connect to the docker host"})
    try:
        return_json, json_url = worker.start_application()
    except ImageScannerClientError as failed_scan:
        return jsonify({'Error': str(failed_scan)})
    return jsonify({'results': return_json,
                    'json_url': json_url,
                    'port': port,
                    'host': host})


@application.errorhandler(404)
def not_found(error):
    ''' Error handler '''
    return flask.make_response(flask.jsonify({'error': 'Not found'}), 404)


@application.route('/reports/<path:path>')
def send_js(path):
    ''' Returns a file from the reports dir '''
    return send_from_directory('/var/tmp/image-scanner/reports/', path)


def get_env_info():
    conf_file = "/etc/image-scanner/image-scanner.conf"
    config = ConfigParser.RawConfigParser()
    # docker_host = "unix://var/run/docker.sock"
    try:
        # Check if we have a conf file
        config.read(conf_file)
        # If we find a conf-file, override it if passed via command line
        # else use the conf-file
        port = config.get('main', 'port')
        host = config.get('main', 'hostip')
        dockerhost = config.get('main', 'dockerhost')
    except ConfigParser.NoSectionError:
        # No conf file found
        raise

    return port, host, dockerhost

if __name__ == '__main__':
    # FIXME
    # I'm not dead sure this is 100% a good idea, but in order
    # to avoid issues....
    if os.geteuid() is not 0:
        print "rest must be run as root"
        sys.exit(1)

    parser = argparse.ArgumentParser(description='Scan Utility for Containers')
    parser.add_argument('-i', '--hostip', help='host IP to run on',
                        default=None)
    parser.add_argument('-p', '--port', help='port to run on', default=None)
    parser.add_argument('-d', '--dockerhost', default=None,
                        help='Specify docker host socket to use')

    args = parser.parse_args()

    port, host, dockerhost = get_env_info()

    # Checking inputs which can come from command_line,
    # defaults, or config_file

    application.run(debug=True, host=host, port=int(port))
