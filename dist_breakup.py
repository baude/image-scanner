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

import xml.etree.ElementTree as ET
import os
import tarfile


class PlatformTree(object):
    def __init__(self, root):
        self.nt_root = ET.Element(root.tag)
        self.nt_root.attrib = root.attrib

        _generator = root.find("{http://oval.mitre.org/XMLSchema/oval-defi"
                               "nitions-5}generator")

        self.nt_root.append(_generator)

        self.def_root = ET.Element("{http://oval.mitre.org/XMLSchema/oval-def"
                                   "initions-5}definitions")
        self.def_tests = ET.Element("{http://oval.mitre.org/XMLSchema/oval-def"
                                    "initions-5}tests")
        self.def_objects = ET.Element("{http://oval.mitre.org/XMLSchema/oval-d"
                                      "efinitions-5}objects")
        self.def_states = ET.Element("{http://oval.mitre.org/XMLSchema/oval"
                                     "-definitions-5}states")

        # Add the base roots
        self.nt_root.append(self.def_root)
        self.nt_root.append(self.def_tests)
        self.nt_root.append(self.def_objects)
        self.nt_root.append(self.def_states)

        # Dicts that keep track of tests, states, object
        # nodes as they get added to each new tree

        self.added_tests = []
        self.added_states = []
        self.added_objects = []


class CVEParse(object):
    def __init__(self, workdir):
        self.workdir = workdir
        self.dist_tar = os.path.join(self.workdir, "dist_files.tar")
        self.platform_dict = {}
        self.tests_dict = {}
        self.objects_dict = {}
        self.states_dict = {}
        self.platform_hash = {}
        self.out_names = []
        self.super_names = ['Red Hat Enterprise Linux 3',
                            'Red Hat Enterprise Linux 4',
                            'Red Hat Enterprise Linux 5',
                            'Red Hat Enterprise Linux 6',
                            'Red Hat Enterprise Linux 7']

        self.xmlf = os.path.join(self.workdir, "com.redhat.rhsa-all.xml")

    def create_platform_hash(self):

        platforms = self.root.findall(".//{http://oval.mitre.org/XMLSchema/"
                                      "oval-definitions-5}platform")
        platform_names = []
        for name in platforms:
            if name.text not in platform_names:
                platform_names.append(name.text)

        if None in platform_names:
            platform_names.remove(None)

        for name in platform_names:
            for supern in self.super_names:
                if name.find(supern) > -1:
                    self.platform_hash[name] = supern
                    break

        for platform in platform_names:
            if (platform not in self.platform_hash.keys()) \
                    and (platform is not None):
                print "Adding non-RHEL platform {0}".format(platform)
                self.platform_hash[platform] = platform

    def write_xml(self):
        for k in self.platform_dict.keys():
            out_tree = ET.ElementTree(self.platform_dict[k].nt_root)
            if k is None:
                out_name = "None"
            else:
                out_name = os.path.join(self.workdir,
                                        k.replace(" ", "_") + ".xml")
                self.out_names.append(out_name)
            out_tree.write(out_name)

    def create_tar(self):
        tar = tarfile.open(self.dist_tar, 'w')
        for outfile in self.out_names:
            tar.add(outfile)
        tar.close()

    def _create_dicts(self):
        tests = self.root.findall("{http://oval.mitre.org/XMLSchema/oval"
                                  "-definitions-5}tests/*")
        objects = self.root.findall("{http://oval.mitre.org/XMLSchema/"
                                    "oval-definitions-5}objects/*")
        states = self.root.findall("{http://oval.mitre.org/XMLSchema/"
                                   "oval-definitions-5}states/*")

        for test in tests:
            self.tests_dict[test.attrib['id']] = test

        for obj in objects:
            self.objects_dict[obj.attrib['id']] = obj

        for state in states:
            self.states_dict[state.attrib['id']] = state

    def def_walker(self, definition):
        platforms = definition.findall("{http://oval.mitre.org/XMLSchema/"
                                       "oval-definitions-5}metadata/{http"
                                       "://oval.mitre.org/XMLSchema/oval-"
                                       "definitions-5}affected/{http://oval"
                                       ".mitre.org/XMLSchema/oval-definitions"
                                       "-5}platform")

        for platform in platforms:
            if platform.text is None:
                continue
            plat_name = self.platform_hash[platform.text]
            if plat_name not in self.platform_dict.keys():
                self.platform_dict[plat_name] = PlatformTree(self.root)

            self.platform_dict[plat_name].def_root.append(definition)

            criterion = definition.findall("{http://oval.mitre.org/XMLSchema/"
                                           "oval-definitions-5}criteria//{http"
                                           "://oval.mitre.org/XMLSchema/oval-"
                                           "definitions-5}criterion")
            for crit in criterion:
                test = self.tests_dict[crit.attrib['test_ref']]

                if crit.attrib['test_ref'] not in \
                        self.platform_dict[plat_name].added_tests:
                    self.platform_dict[plat_name].added_tests.append(
                        crit.attrib['test_ref'])
                    self.platform_dict[plat_name].def_tests.append(test)

                _object_ref = test.find("{http://oval.mitre.org/XMLSchema/"
                                        "oval-definitions-5#linux}object")
                _state_ref = test.find("{http://oval.mitre.org/XMLSchema/"
                                       "oval-definitions-5#linux}state")

                obj_node = self.objects_dict[_object_ref.attrib['object_ref']]
                if _object_ref.attrib['object_ref'] not in \
                        self.platform_dict[plat_name].added_objects:
                    self.platform_dict[plat_name].added_objects.append(
                        _object_ref.attrib['object_ref'])
                    self.platform_dict[plat_name].def_objects.append(obj_node)

                state_node = self.states_dict[_state_ref.attrib['state_ref']]
                if _state_ref.attrib['state_ref'] not in \
                        self.platform_dict[plat_name].added_states:
                    self.platform_dict[plat_name].added_states.append(
                        _state_ref.attrib['state_ref'])
                    self.platform_dict[plat_name].def_states.append(state_node)

        self.thread_complete.append(definition)

    def parse_for_platform(self):
        self.tree = ET.parse(self.xmlf)
        self.root = self.tree.getroot()
        self.create_platform_hash()
        self.definitions = self.root.find("{http://oval.mitre.org/XMLSchema/"
                                          "oval-definitions-5}definitions")
        self.test_root = self.root.find("{http://oval.mitre.org/XMLSchema/"
                                        "oval-definitions-5}tests")
        self._create_dicts()
        self.thread_complete = []
        for definition in self.definitions.getchildren():
            self.def_walker(definition)
        self.write_xml()
