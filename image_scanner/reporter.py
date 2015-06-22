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
import urlparse


class Reporter(object):
    ''' Does stdout reporting '''
    def __init__(self):
        self.output = collections.namedtuple('Summary', 'iid, cid, os, sevs,'
                                             'log, msg',)
        self.list_of_outputs = []
        self.appc = ApplicationConfiguration()
        self.report_dir = os.path.join(self.appc.reportdir, "openscap_reports")
        self.appc.docker_state = os.path.join(self.report_dir,
                                              "docker_state.json")

        if not os.path.exists(self.report_dir):
            os.mkdir(self.report_dir)
        self.content = ""

    def add_content(self, content):
        self.content = self.content + content

    def report_summary(self):
        '''
        This function is the primary function to output results
        to stdout when running the image-scanner
        '''
        self.appc._print("Summary:")
        if self.appc.api:
            baseurl = urlparse.urljoin(self.appc.url_root,
                                       os.path.basename(self.report_dir))
            self.appc.json_url = baseurl + '/docker_state.json'
        for image in self.list_of_outputs:
            short_cid_list = []
            dtype = self._get_dtype(image.iid)
            self.appc._print("{0}{1}: {2}".format(" " * 5, dtype, image.iid))
            if self.appc.api:
                image_json = {image.iid: {}}
                image_json[image.iid]['http_url'] = \
                    baseurl + "/{0}.html".format(image.iid)

                image_json[image.iid]['xml_url'] = \
                    baseurl + "/{0}.xml".format(image.iid)

            if image.msg is None:
                html_p = "<tr><td><b>{0}</b>:<td colspan=2><a href='{1}.html'>{2}</a></td></tr>".format(dtype, image.iid, image.iid)
                self.add_content(html_p) 
                for cid in image.cid:
                    short_cid_list.append(cid[:12])
                if self.appc.api:
                    image_json[image.iid]['cids'] = short_cid_list
                self.appc._print("{0}OS: {1}".format(" " * 5, image.os.rstrip()))
                html_p = "<tr><td>{0}</td><td><b>OS:</b></td><td>{1}</td></tr>".format(" " * 5, image.os.rstrip())
                self.add_content(html_p)
                if dtype is not "Container":
                    self.appc._print("{0}Containers affected "
                          "({1}): {2}".format(" " * 5, len(short_cid_list),
                                              ', '.join(short_cid_list)))
                    html_p = "<tr><td>{0}</td><td><b>Containers affected:</b></td><td>" \
                          "({1}): {2}</td></tr>".format(" " * 5, len(short_cid_list),
                                              ', '.join(short_cid_list))
                    self.add_content(html_p)
                self.appc._print("{0}Results: Critical({1}) Important({2}) Moderate({3})"\
                        " Low({4})".format(" " * 5, image.sevs['Critical'],
                                         image.sevs['Important'],
                                         image.sevs['Moderate'],
                                         image.sevs['Low']))
                html_p = "<tr><td>{0}</td><td><b>Results:</b></td><td>Critical({1}) Important({2}) Moderate({3})"\
                        " Low({4})</td></tr>".format(" " * 5, image.sevs['Critical'],
                                         image.sevs['Important'],
                                         image.sevs['Moderate'],
                                         image.sevs['Low'])
                self.add_content(html_p)
                if self.appc.api:
                    image_json[image.iid]['critical'] = image.sevs['Critical']
                    image_json[image.iid]['important'] = image.sevs['Important']
                    image_json[image.iid]['moderate'] = image.sevs['Moderate']
                    image_json[image.iid]['low'] = image.sevs['Low']
                self.appc._print("")
            else:
                html_p = "<tr><td><b>{0}</b>:<td colspan=2>{1}</td></tr>".format(dtype, image.iid)
                self.add_content(html_p) 
                self.appc._print("{0}Results: {1}".format(" " * 5, image.msg))
                html_p =  "<tr><td>{0}</td><td><b>Results</b>:</td><td>{1}</td></tr>".format(" " * 5, image.msg)
                self.add_content(html_p)
                if self.appc.api:
                    image_json[image.iid]['msg'] = image.msg
                self.appc._print("")
            html_p = "<tr><td colspan=3> </td></tr>"
            self.add_content(html_p)
            if self.appc.api:
                self.appc.return_json.append(image_json)
        report_files = []
        for image in self.list_of_outputs:
            if image.msg is None:
                short_image = image.iid[:12] + ".scap"
                out = open(os.path.join(self.report_dir, short_image), 'wb')
                report_files.append(short_image)
                out.write(image.log)
                out.close
        self.appc._print("Writing summary and reports to {0}".format(self.report_dir))
        for report in report_files:
                os.path.join(self.report_dir, report)

        sum_out = open(os.path.join(self.report_dir, "summary.html"), "wb")
        sum_html = """
        <html><body>
        <h2>Summary</h2>
        <table>
        %(content)s
        </table>
        </body>
        </html>
        """ % {'content': self.content}
        sum_out.write(sum_html)
        sum_out.close()

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
