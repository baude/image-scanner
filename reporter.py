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
'''Reporter Class'''

import collections
import os
from applicationconfiguration import ApplicationConfiguration


class Reporter(object):
    ''' Does stdout reporting '''
    def __init__(self):
        self.output = collections.namedtuple('Summary', 'iid, cid, os, sevs,'
                                             'log, msg',)
        self.list_of_outputs = []
        self.appc = ApplicationConfiguration()
        self.report_dir = os.path.join(self.appc.reportdir, "openscap_reports")

        if not os.path.exists(self.report_dir):
            os.mkdir(self.report_dir)

    def report_summary(self):
        '''
        This function is the primary function to output results
        to stdout when running the image-scanner
        '''
        print "Summary:"
        for image in self.list_of_outputs:
            short_cid_list = []
            dtype = self._get_dtype(image.iid)
            print "{0}{1}: {2}".format(" " * 5, dtype, image.iid)
            if image.msg is None:
                for cid in image.cid:
                    short_cid_list.append(cid[:12])
                print "{0}OS: {1}".format(" " * 5, image.os.rstrip())
                if dtype is not "Container":
                    print "{0}Containers affected " \
                          "({1}): {2}".format(" " * 5, len(short_cid_list),
                                              ', '.join(short_cid_list))
                print "{0}Results: Critical({1}) Important({2}) Moderate({3})"\
                      " Low({4})".format(" " * 5, image.sevs['Critical'],
                                         image.sevs['Important'],
                                         image.sevs['Moderate'],
                                         image.sevs['Low'])
                print ""
            else:
                print "{0}Results: {1}".format(" " * 5, image.msg)
                print ""

        report_files = []
        for image in self.list_of_outputs:
            if image.msg is None:
                short_image = image.iid[:12] + ".scap"
                out = open(os.path.join(self.report_dir, short_image), 'wb')
                report_files.append(short_image)
                out.write(image.log)
                out.close

        for report in report_files:
            print "Wrote CVE Summary report: {0}".format(
                os.path.join(self.report_dir, report))

    def _get_dtype(self, iid):
        ''' Returns whether the given id is an image or container '''
        # Images
        for image in self.appc.images:
            if image['Id'].startswith(iid):
                return "Image"
        # Containers
        for con in self.appc.cons:
            if con['Id'].startswith(iid):
                return "Container"
        return None
