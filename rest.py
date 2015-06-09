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
from image_scanner import Worker
import docker
import argparse
import sys

flask_app = flask.Flask(__name__, static_path='/tmp/')
# app.config.update(SERVER_NAME='127.0.0.1:5001')

scan_args = ['allcontainers', 'allimages', 'images', 'logfile', 'nocache',
             'number', 'onlyactive', 'reportdir', 'startweb', 'stopweb',
             'workdir', 'api', 'url_root', 'host']

scan_tuple = collections.namedtuple('Namespace', scan_args)

rest_path = '/image-scanner/api/'

dockerHost = "unix://var/run/docker.sock"
connection = docker.Client(base_url=dockerHost, timeout=10)


def create_tuple(in_args, url_root):
    global scan_args
    global scan_tuple
    global dockerHost
    _tmp_tuple = scan_tuple(allcontainers=False if
                            in_args.get('allcontainers') is None else
                            in_args.get('allcontainers'),
                            allimages=False if in_args.get('allimages') is
                            None else in_args.get('allimages'),
                            images=in_args.get('images') if
                            in_args.get('images') is not None else None,
                            logfile="/tmp/openscap.log" if
                            in_args.get('logfile') is None else
                            in_args.get('logile'),
                            nocache=False if in_args.get('nocache') is None
                            else in_args.get('nocache'),
                            number=2 if in_args.get('number') is None else
                            int(in_args.get('number')),
                            onlyactive=False if in_args.get('onlyactive') is
                            None else in_args.get('onlyactive'),
                            reportdir="/tmp" if in_args.get('reportdir') is
                            None else in_args.get('reportdir'),
                            workdir="/tmp" if in_args.get('workdir') is None
                            else in_args.get('workdir'),
                            stopweb=False,
                            startweb=False,
                            api=True,
                            url_root=url_root,
                            host=dockerHost)
    return _tmp_tuple


@flask_app.route(os.path.join(rest_path, "test"), methods=['GET'])
def get_tasks():
    ''' Test method'''
    return "hello"


@flask_app.route(os.path.join(rest_path, "containers"), methods=['GET'])
def containers():
    '''Returns all containers'''
    global connection
    cons = {'all_containers': connection.containers(all=True)}
    return jsonify(cons)


@flask_app.route(os.path.join(rest_path, "images"), methods=['GET'])
def images():
    '''Returns all images'''
    global connection
    images = {'all_images': connection.images(all=True)}
    return jsonify(images)


@flask_app.route(os.path.join(rest_path, "inspect_container"), methods=['GET'])
def inspect_container():
    ''' Returns inspect data of a container'''
    global connection
    inspect_data = connection.inspect_container(request.json['cid'])
    return jsonify(inspect_data)


@flask_app.route(os.path.join(rest_path, "inspect_image"), methods=['GET'])
def inspect_image():
    ''' Returns inspect data of an image'''
    global connection
    inspect_data = connection.inspect_image(request.json['iid'])
    return jsonify(inspect_data)


@flask_app.route(os.path.join(rest_path, "scan"), methods=['GET'])
def scan():
    ''' Kicks off a scan via REST '''
    arg_tup = create_tuple(request.json, request.url_root)
    worker = Worker(arg_tup)
    return_json = worker.start_application()
    return jsonify({'results': return_json})


@flask_app.errorhandler(404)
def not_found(error):
    ''' Error handler '''
    return flask.make_response(flask.jsonify({'error': 'Not found'}), 404)


@flask_app.route('/openscap_reports/<path:path>')
def send_js(path):
    ''' Returns a file from the openscap_reports dir '''
    return send_from_directory('/tmp/openscap_reports', path)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Scan Utility for Containers')
    parser.add_argument('-i', '--hostip', help='host IP to run on',
                        default="127.0.0.1")
    parser.add_argument('-p', '--port', help='port to run on', default="5000")
    parser.add_argument('-H', '--host', default='unix://var/run/docker.sock',
                        help='Specify docker host socket to use')

    args = parser.parse_args()

    try:
        dockerHost = args.host
        connection = docker.Client(base_url=dockerHost, timeout=10)
        if not connection.ping():
            raise(Exception)
    except Exception, err:
        print 'Cannot connect to the Docker daemon. ' \
              'Is \'docker -d\' running on this host?'
        sys.exit(1)

    flask_app.run(debug=True, host=args.hostip, port=int(args.port))
