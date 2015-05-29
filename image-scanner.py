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
import urllib2
import bz2
import timeit
import argparse
import threading
import logging
import sys
import time
from dist_breakup import CVEParse
from applicationconfiguration import ApplicationConfiguration
from reporter import Reporter
from scan import Scan


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


class Worker(object):
    def __init__(self, args):
        self.procs = args.number
        self.ac = ApplicationConfiguration(parserargs=args)
        self.cs = ContainerSearch()
        self.output = Reporter()
        self.cve_file = os.path.join(self.ac.workdir,
                                     "com.redhat.rhsa-all.xml")
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
        f = Scan(image, cids, output)
        if f.get_release():

            t = timeit.Timer(f.scan).timeit(number=1)
            logging.debug("Scanned chroot for image {0}"
                          " completed in {1} seconds"
                          .format(image, t))

            timeit.Timer(f.report_results).timeit(number=1)
        else:
            # This is not a RHEL image or container
            f._report_not_rhel(image)

        # t = timeit.Timer(f.clean_up_chroot).timeit(number=1)
        start = time.time()
        f.DM.cleanup(f.dm_results)
        logging.debug("Removing temporary chroot for image {0} completed in"
                      " {1} seconds".format(image, time.time() - start))
        self.threads_complete += 1

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

work = Worker(args)
work.start_application()
