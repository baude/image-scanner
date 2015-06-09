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

''' Starts an uwsgi instance of our flash REST API '''

import subprocess
import ConfigParser
import threading

conf_file = "/etc/image-scanner/image-scanner.conf"
config = ConfigParser.RawConfigParser()

try:
    # Check if we have a conf file
    config.read(conf_file)
    # If we find a conf-file, override it if passed via command line
    # else use the conf-file
    port = config.get('main', 'port')
    host = config.get('main', 'hostip')

except ConfigParser.NoSectionError as conf_error:
    # No conf file found, resort to checking command line, then defaults
    port = 5001
    host = "127.0.0.1"


host_port = "{0}:{1}".format(host, port)
cmd = ['uwsgi', '--plugin', 'python,http', '--socket', host_port,  '--protocol=http', '--wsgi-file', '/usr/lib/python2.7/site-packages/rest.py']
subprocess.call(cmd)
