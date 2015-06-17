import sys

def application(env, start_response):
    start_response('200 OK', [('Content-Type','text/html')])
    sys.exit(0) 
    return [b"Hello World"]
