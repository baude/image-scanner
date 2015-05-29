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

import collections
import os
from applicationconfiguration import ApplicationConfiguration


class Reporter(object):
    def __init__(self):
        self.output = collections.namedtuple('Summary', 'iid, cid, os, sevs,'
                                             'log')
        self.list_of_outputs = []
        self.ac = ApplicationConfiguration()
        self.report_dir = os.path.join(self.ac.reportdir, "openscap_reports")

        if not os.path.exists(self.report_dir):
            os.mkdir(self.report_dir)

    def report_summary(self):
        print "Summary:"
        for image in self.list_of_outputs:
            short_cid_list = []
            for cid in image.cid:
                short_cid_list.append(cid[:12])
            print "{0}Image: {1}".format(" " * 5, image.iid)
            print "{0}OS: {1}".format(" " * 5, image.os.rstrip())
            print "{0}Containers affected " \
                  "({1}): {2}".format(" " * 5, len(short_cid_list),
                                      ', '.join(short_cid_list))
            print "{0}Results: Critical({1}) Important({2}) Moderate({3}) " \
                  "Low({4})".format(" " * 5, image.sevs['Critical'],
                                    image.sevs['Important'],
                                    image.sevs['Moderate'],  image.sevs['Low'])
            print ""

        report_files = []
        for image in self.list_of_outputs:
            short_image = image.iid[:12] + ".scap"
            out = open(os.path.join(self.report_dir, short_image), 'wb')
            report_files.append(short_image)
            out.write(image.log)
            out.close

        for report in report_files:
            print "Wrote CVE Summary report: {0}".format(
                os.path.join(self.report_dir, report))
