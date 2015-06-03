import flask
import os
import collections
from flask import make_response, jsonify, request, send_from_directory
from image_scanner import Worker

app = flask.Flask(__name__, static_path='/tmp/')
#app = flask.Flask(__name__)
#app.config.update(SERVER_NAME='127.0.0.1:5001')

scan_args = ['allcontainers', 'allimages', 'images', 'logfile', 'nocache',
             'number', 'onlyactive', 'reportdir', 'startweb', 'stopweb',
             'workdir', 'api', 'url_root']
scan_tuple = collections.namedtuple('Namespace', scan_args)

rest_path = '/image-scanner/api/'


def create_tuple(in_args, url_root):
    global scan_args
    global scan_tuple

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
                            url_root=url_root)
    return _tmp_tuple

@app.route(os.path.join(rest_path, "test"), methods=['GET'])
def get_tasks():
    print request.url_root
    print request.remote_addr
    return "hello"

@app.route(os.path.join(rest_path, "scan"), methods=['GET', 'POST', 'PUT'])
def scan():
    print request.json
    arg_tup = create_tuple(request.json, request.url_root)
    worker = Worker(arg_tup)
    return_json = worker.start_application()
    return jsonify({'results': return_json})

@app.errorhandler(404)
def not_found(error):
    return flask.make_response(flask.jsonify({'error': 'Not found'}), 404)

@app.route('/openscap_reports/<path:path>')
def send_js(path):
    print path
    return send_from_directory('/tmp/openscap_reports', path)

if __name__ == '__main__':
    app.run(debug=True)
