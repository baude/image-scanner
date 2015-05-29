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

import os
import docker
import platform
import subprocess
import urllib2
import bz2
import timeit
import shutil
import xml.etree.ElementTree as ET
import collections
import argparse
import threading
import StringIO
import logging
import sys
import time
from dist_breakup import CVEParse
from docker_mount import DockerMount

# Monkey patch for tarfile courtesy of vbatts
from xtarfile import tarfile


class Singleton(object):
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


class ContainerSearch(object):
    def __init__(self):
        if not os.path.exists("/var/run/docker.pid"):
            print "Error: Docker does not appear to be running"
            sys.exit(0)
        self.c = docker.Client(base_url='unix://var/run/docker.sock',
                               timeout=10)
        self.cons = self.c.containers(all=True)
        self.active_containers = self.c.containers(all=False)
        self.images = self.c.images(name=None,
                                    quiet=False, all=True, viz=False)
        self.imagelist = self._returnImageList(self.images)
        self.fcons = self._formatCons(self.cons)
        self.fcons_active = self._formatCons(self.active_containers)
        self.ac = ApplicationConfiguration()
        self.ac.fcons = self.fcons

    def _returnImageList(self, images):
        '''
        Walks through the image list and if the image
        size is not 0, it will add it to the returned
        list.
        '''

        il = []
        for i in images:
            if i['VirtualSize'] > 0:
                il.append(i['Id'])
        return il

    def _formatCons(self, cons):

        # Changed, this needs fixing
        '''
        Returns a formatted dictionary of containers by
        image id like:

        fcons = {'iid': [{'cid': {'running': bool}}, ... ]}
        '''
        fcons = {}
        for c in cons:
            cid = c['Id']
            inspect = self.c.inspect_container(cid)
            iid = inspect['Image']
            run = inspect['State']['Running']
            if iid not in fcons:
                fcons[iid] = [{'uuid': cid, 'running': run}]
            else:
                fcons[iid].append({'uuid': cid, 'running': run})
        return fcons


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


class foo(object):
    def __init__(self, image_uuid, con_uuids, output):
        self.c = docker.Client(base_url='unix://var/run/docker.sock',
                               timeout=10)
        self.image_name = image_uuid
        self.ac = ApplicationConfiguration()
        self.tb_location = os.path.join(self.ac.workdir,
                                        self.image_name + ".tar")
        self.CVEs = collections.namedtuple('CVEs', 'title, severity,'
                                           'cve_ref_id, cve_ref_url,'
                                           'rhsa_ref_id, rhsa_ref_url')

        self.list_of_CVEs = []
        self.con_uuids = con_uuids
        self.output = output
        self.report_dir = os.path.join(self.ac.workdir, "openscap_reports")
        if not os.path.exists(self.report_dir):
            os.mkdir(self.report_dir)

        start = time.time()
        self.DM = DockerMount("/tmp")
        self.dm_results = self.DM.mount(image_uuid)
        logging.debug("Created scanning chroot in {0}"
                      " seconds".format(time.time() - start))
        self.dest = self.dm_results.mount_path

    def get_release(self):
        etc_release_path = os.path.join(self.dest, "rootfs",
                                        "etc/redhat-release")

        if not os.path.exists(etc_release_path):
            logging.info("{0} is not RHEL based".format(self.image_name))
            return False

        self.os_release = open(etc_release_path).read()

        rhel = 'Red Hat Enterprise Linux'

        if rhel in self.os_release:
            logging.debug("{0} is {1}".format(self.image_name,
                                              self.os_release.rstrip()))
            return True
        else:
            logging.info("{0} is {1}".format(self.image_name,
                                             self.os_release.rstrip()))
            return False

    def scan(self):
        logging.debug("Scanning chroot {0}".format(self.image_name))
        hostname = open("/etc/hostname").read().rstrip()
        os.environ["OSCAP_PROBE_ARCHITECTURE"] = platform.processor()
        os.environ["OSCAP_PROBE_ROOT"] = os.path.join(self.dest, "rootfs")
        os.environ["OSCAP_PROBE_OS_NAME"] = platform.system()
        os.environ["OSCAP_PROBE_OS_VERSION"] = platform.release()
        os.environ["OSCAP_PROBE_"
                   "PRIMARY_HOST_NAME"] = "{0}:{1}".format(hostname,
                                                           self.image_name)

        # We only support RHEL 6|7 in containers right now

        if "Red Hat Enterprise Linux" in self.os_release:
            if "7." in self.os_release:
                self.chroot_cve_file = os.path.join(
                    self.ac.workdir, "Red_Hat_Enterprise_Linux_7.xml")
            if "6." in self.os_release:
                self.chroot_cve_file = os.path.join(
                    self.ac.workdir, "Red_Hat_Enterprise_Linux_6.xml")

        cmd = ['oscap', 'oval', 'eval', '--report',
               os.path.join(self.report_dir,
                            self.image_name + '.html'),
               '--results',
               os.path.join(self.report_dir,
                            self.image_name + '.xml'), self.chroot_cve_file]

        self.result = subprocess.check_output(cmd)

    def capture_run(self, cmd):
        '''
        Subprocess command that captures and returns the output and
        return code.
        '''

        r = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        return r.communicate(), r.returncode

    def get_cons(self, fcons, short_iid):
        cons = []
        for image in fcons:
            if image.startswith(short_iid):
                for con in fcons[image]:
                    cons.append(con['uuid'][:12])
        return cons

    def report_results(self):
        cve_tree = ET.parse(self.chroot_cve_file)
        self.cve_root = cve_tree.getroot()

        for line in self.result.splitlines():
            split_line = line.split(':')
            # Not in love with how I did this
            # Should find a better marked to know if it is a line
            # a parsable line.
            if (len(split_line) == 5) and ('true' in split_line[4]):
                self._return_xml_values(line.split()[1][:-1])

        sev_dict = {}
        sum_log = StringIO.StringIO()
        sum_log.write("Image: {0} ({1})".format(self.image_name,
                                                self.os_release))
        cons = self.get_cons(self.ac.fcons, self.image_name)
        sum_log.write("\nContainers based on this image ({0}): {1}\n"
                      .format(len(cons), ", ".join(cons)))
        for sev in ['Critical', 'Important', 'Moderate', 'Low']:
            sev_counter = 0
            for cve in self.list_of_CVEs:
                if cve.severity == sev:
                    sev_counter += 1
                    sum_log.write("\n")
                    fields = list(self.CVEs._fields)
                    fields.remove('title')
                    sum_log.write("{0}{1}: {2}\n"
                                  .format(" " * 5, "Title",
                                          getattr(cve, "title")))

                    for field in fields:
                        sum_log.write("{0}{1}: {2}\n"
                                      .format(" " * 10, field.title(),
                                              getattr(cve, field)))
            sev_dict[sev] = sev_counter
        self.output.list_of_outputs.append(
            self.output.output(iid=self.image_name, cid=self.con_uuids,
                               os=self.os_release, sevs=sev_dict,
                               log=sum_log.getvalue()))
        sum_log.close()

    def _return_xml_values(self, cve):
        cve_string = ("{http://oval.mitre.org/XMLSchema/oval-definitions-5}"
                      "definitions/*[@id='%s']" % cve)
        cve_xml = self.cve_root.find(cve_string)
        title = cve_xml.find("{http://oval.mitre.org/XMLSchema/oval-definitions"
                             "-5}metadata/{http://oval.mitre.org/XMLSchema/"
                             "oval-definitions-5}title")
        cve_id = cve_xml.find("{http://oval.mitre.org/XMLSchema/"
                              "oval-definitions-5}metadata/{http://oval.mitre."
                              "org/XMLSchema/oval-definitions-5}reference"
                              "[@source='CVE']")
        sev = (cve_xml.find("{http://oval.mitre.org/XMLSchema/oval-definitions"
                            "-5}metadata/{http://oval.mitre.org/XMLSchema/oval"
                            "-definitions-5}advisory/")).text

        if cve_id is not None:
            cve_ref_id = cve_id.attrib['ref_id']
            cve_ref_url = cve_id.attrib['ref_url']
        else:
            cve_ref_id = None
            cve_ref_url = None

        rhsa_id = cve_xml.find("{http://oval.mitre.org/XMLSchema/oval-"
                               "definitions-5}metadata/{http://oval.mitre.org"
                               "/XMLSchema/oval-definitions-5}reference"
                               "[@source='RHSA']")

        if rhsa_id is not None:
            rhsa_ref_id = rhsa_id.attrib['ref_id']
            rhsa_ref_url = rhsa_id.attrib['ref_url']
        else:
            rhsa_ref_id = None
            rhsa_ref_url = None

        self.list_of_CVEs.append(
            self.CVEs(title=title.text, cve_ref_id=cve_ref_id,
                      cve_ref_url=cve_ref_url, rhsa_ref_id=rhsa_ref_id,
                      rhsa_ref_url=rhsa_ref_url, severity=sev))

    def clean_up_chroot(self):
        logging.debug("Removing temporary chroot at {0}".format(self.dest))
        shutil.rmtree(self.dest)
        logging.debug("Removing temporary tarball {0}"
                      .format(self.tb_location))


class Worker(object):
    def __init__(self, args):
        self.procs = args.number
        self.cs = ContainerSearch()
        self.output = Reporter()
        self.ac = ApplicationConfiguration()
        self.cve_file = os.path.join(self.ac.workdir, "com.redhat.rhsa-all.xml")
        self.cve_file_bz = os.path.join(self.ac.workdir,
                                        "com.redhat.rhsa-all.xml.bz2")

    def _get_cids_for_image(self, cs, image):
            cids = []
            if image in cs.fcons:
                for container in cs.fcons[image]:
                    cids.append(container['uuid'])
            return cids

    def get_cve_data(self):

        # FIXME
        # Wrap this in an exception

        hdr = {'User-agent': 'Mozilla/5.0'}
        url = ("http://www.redhat.com/security/data/oval/"
               "com.redhat.rhsa-all.xml.bz2")

        print "Obtaining CVE file data from {0}".format(url)

        bar = urllib2.Request(url, "", hdr)
        resp = urllib2.urlopen(bar)
        fh = open(self.cve_file_bz, "w")
        fh.write(resp.read())
        fh.close()

    def extract_cve_data(self):
        # Extract the XML bz
        bzfile = bz2.BZ2File(self.cve_file_bz)
        cve_data = bzfile.read()
        open(self.cve_file, 'wb').write(cve_data)

    def return_active_threadnames(self, threads):
        thread_names = []
        for thread in threads:
            thread_name = thread._Thread__name
            if thread_name is not "MainThread":
                thread_names.append(thread_name)

        return thread_names

    def only_containers(self, running):
        image_list = []
        # Rid ourselves of 0 size containers
        for i in self.cs.fcons.keys():
            for container in self.cs.fcons[i]:
                if container['running'] in running:
                    if (i not in image_list) and (i in self.cs.imagelist):
                        image_list.append(i)
        if len(image_list) == 0:
            print "There are no containers on this system"
            sys.exit(1)
        self._do_work(image_list)

    def allimages(self):
        if len(self.cs.imagelist) == 0:
            print "There are no images on this system"
            sys.exit(1)
        self._do_work(self.cs.imagelist)

    def list_of_images(self, image_list):
        self._do_work(image_list)

    def allcontainers(self):
        image_list = []
        for i in self.cs.fcons.keys():
            if (len(i) > 0) and (i not in image_list):
                image_list.append(i)
        if len(image_list) == 0:
            print "There are no containers on this system"
            sys.exit(1)
        self._do_work(image_list)

    def _do_work(self, image_list):
        cp = CVEParse(self.ac.workdir)
        if (not os.path.exists(cp.xmlf)) or \
                (self.ac.nocache) or \
                ((time.time() - os.path.getmtime(cp.xmlf)) / (60**2) > 12):
            # If we find a tarball of the dist break outs and
            # it is less than 12 hours old, use it to speed things
            # up

            self.get_cve_data()
            self.extract_cve_data()
            cp.create_tar()

            print "Splitting master XML file into distribution " \
                  "specific XML files"

            # Run dist breakout to make dist specific XML
            # files
            t = timeit.Timer(cp.parse_for_platform).timeit(number=1)
            logging.debug("Parsed distribution breakup in "
                          "{0} seconds".format(t))
        print "\nBegin processing\n"
        threads = []

        for image in image_list:
            cids = self._get_cids_for_image(self.cs, image)
            t = threading.Thread(target=self.search_containers, name=image,
                                 args=(image, cids, self.output,))
            threads.append(t)

        logging.info("Number of containers to scan: {0}".format(len(threads)))
        total_images = len(threads)
        self.threads_complete = 0
        print ""
        while len(threads) > 0:
            if len(threading.enumerate()) < self.procs:
                new_thread = threads.pop()
                new_thread.start()
                self._progress(float(self.threads_complete),
                               float(total_images))

        while len(threading.enumerate()) > 1:
            self._progress(float(self.threads_complete), float(total_images))
            time.sleep(1)
            pass

        self._progress(float(self.threads_complete), float(total_images))
        print "\n" * 2
        self.output.report_summary()

    def _progress(self, complete, total):
        sys.stdout.write("\r[{0:20s}] {1}%    {2}/{3}"
                         .format('#' * int(complete/total * 20),
                                 int(complete/total * 100),
                                 int(complete), int(total)))
        sys.stdout.flush()

    def search_containers(self, image, cids, output):
        f = foo(image, cids, output)
        if f.get_release():

            t = timeit.Timer(f.scan).timeit(number=1)
            logging.debug("Scanned chroot for image {0}"
                          " completed in {1} seconds"
                          .format(image, t))

            timeit.Timer(f.report_results).timeit(number=1)

        # t = timeit.Timer(f.clean_up_chroot).timeit(number=1)
        start = time.time()
        f.DM.cleanup(f.dm_results)
        logging.debug("Removing temporary chroot for image {0} completed in"
                      " {1} seconds".format(image, time.time() - start))
        self.threads_complete += 1


class ApplicationConfiguration(Singleton):
    def _singleton_init(self, parserargs=None):
        super(ApplicationConfiguration, self)._singleton_init()
        self.workdir = parserargs.workdir
        self.logfile = parserargs.logfile
        self.number = parserargs.number
        self.reportdir = parserargs.reportdir
        self.nocache = parserargs.nocache

    def __init__(self, parserargs=None):
        pass

    def start_application(self):
        start_time = time.time()
        logging.basicConfig(filename=args.logfile,
                            format='%(asctime)s %(levelname)-8s %(message)s',
                            datefmt='%m-%d %H:%M', level=logging.DEBUG)
        work = Worker(args)

        if args.onlyactive:
            work.only_containers(running=[True])
        if args.allcontainers:
            work.allcontainers()
        if args.allimages:
            work.allimages()
        if args.images:
            # Check to make sure we have a valid image list
            for image in args.images:
                if not any(found.startswith(image)
                           for found in work.cs.imagelist):
                    print "{0} is not a valid image ID".format(image)
                    sys.exit(1)
            work.list_of_images(args.images)

        end_time = time.time()
        duration = (end_time - start_time)

        if duration < 60:
            unit = "seconds"
        else:
            unit = "minutes"
            duration = duration/60

        logging.info("Completed entire scan in {0} {1}".format(duration, unit))

parser = argparse.ArgumentParser(description='Scan Utility for Containers')
group = parser.add_mutually_exclusive_group()

group.add_argument('--allimages', help='search all images', default=False,
                   action='store_true')
group.add_argument('--onlyactive', help='search only active containers',
                   default=False, action='store_true')
group.add_argument('--allcontainers', help='search all containers',
                   default=False, action='store_true')
group.add_argument('-i', '--images', help='image to search', action='append')
parser.add_argument('-n', '--number', help='number of processors to use',
                    type=int, default=2)
parser.add_argument('-l', '--logfile', help='logfile to use',
                    default="/tmp/openscap.log")
parser.add_argument('-r', '--reportdir', help='directory to store reports',
                    default="/tmp")

parser.add_argument('-w', '--workdir', help='workdir to use, defaults to /tmp',
                    default="/tmp")
parser.add_argument('--nocache', default=False, help='Do not cache anything',
                    action='store_true')

args = parser.parse_args()


if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)


ac = ApplicationConfiguration(parserargs=args)
ac.start_application()
