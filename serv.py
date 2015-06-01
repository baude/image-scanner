import cherrypy
import os
import sys
import multiprocessing


class IndexBase(object):
    def index(self, **args):
        index = self._formatPage("summary.html", "index", self.index_sub)
        return index


class Stop():
    exposed = True

    @cherrypy.expose
    def GET(self):
        sys.exit(0)


class NodeCherryServer(object):
    def __init__(self, workdir):
        self.workdir = os.path.join(workdir, "openscap_reports")
        p = multiprocessing.Process(target=self.startUp)
        p.start()
        print "You can access your results at: http://localhost:8001" + "/summary.html"

    def startUp(self):
        cherrypy.process.plugins.Daemonizer(cherrypy.engine).subscribe()
        conf = {'/':
                {'request.dispatch': cherrypy.dispatch.MethodDispatcher(),
                 'tools.sessions.on': True,
                 'tools.response_headers.on': True,
                 'tools.response_headers.headers': [('Content-Type',
                                                     'text/plain')],
                 'tools.sessions.on': True,
                 'tools.staticdir.root': os.path.abspath(os.getcwd()),
                 },
                }
        static_conf = {'/':
                       {'tools.sessions.on': True,
                        'tools.staticdir.root': self.workdir,
                        'tools.sessions.on': True,
                        'tools.response_headers.on': True
                        },
                       '/': {
                        'tools.staticdir.root': self.workdir,
                           'tools.staticdir.on': True,
                                   'tools.staticdir.dir': ''
                                   }
                       }
        cherrypy.config.update({'server.socket_port': 8001, 'server.socket_host': '0.0.0.0'})
        cherrypy.config.update({'environment': 'embedded'})
        cherrypy.tree.mount(IndexBase(), '/', static_conf)
        cherrypy.tree.mount(Stop(), '/stop', conf)
        cherrypy.engine.start()
        cherrypy.engine.block()


class StartWeb(object):
    def __init__(self, workdir):
        NodeCherryServer(workdir)
