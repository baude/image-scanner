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

''' Class to handle references '''

import docker
import sys


class Singleton(object):
    ''' Singleton class to pass references'''
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            instance = super(Singleton, cls).__new__(cls)
            instance._singleton_init(*args, **kwargs)
            cls._instance = instance
        return cls._instance

    def __init__(self, *args, **kwargs):
        pass

    def _singleton_init(self, *args, **kwargs):
        """Initialize a singleton instance before it is registered."""
        pass


class ApplicationConfiguration(Singleton):
    '''Application Configuration'''
    def _singleton_init(self, parserargs=None):
        ''' Init for Application Configuration '''
        super(ApplicationConfiguration, self)._singleton_init()
        self.workdir = parserargs.workdir
        self.logfile = parserargs.logfile
        self.number = parserargs.number
        self.reportdir = parserargs.reportdir
        self.nocache = parserargs.nocache
        if not hasattr(parserargs, 'api'):
            self.api = False
        else:
            self.api = bool(parserargs.api)
        if self.api:
            self.url_root = parserargs.url_root
        self.cons = None
        self.images = None
        self.return_json = []
        self.conn = self.ValidateHost(parserargs.host)

    def ValidateHost(self, host):

        try:
            client = docker.Client(base_url=host, timeout=10)
            if not client.ping():
                raise(Exception)
        except Exception, err:
            print 'Cannot connect to the Docker daemon. ' \
                  'Is \'docker -d\' running on this host?'
            sys.exit(1)

        return client

    def _print(self, msg):
        if not self.api:
            print msg

    def __init__(self, parserargs=None):
        ''' init '''
        pass
