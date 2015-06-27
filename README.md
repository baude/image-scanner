# image-scanner

### About

The image-scanner is a multi-faceted scanner for CVEs in containers and images.  Upon scanning a container or image, it then produces a report of any vulnerabilities found.  The image-scanner uses openscap to determine any vulnerabilities.

The image-scanner can be run on the command line but it is designed to be driven by a Python client API via REST.  In fact, our primary use case is for it to be run as "middleware" where using provided APIs, the consumer can take the common output data and transform it into something useful for their environment or application.  The image-scanner can also run parallel scans to speed up results.

As of this writing, the image-scanner can only scan Red Hat Enterprise based containers and images due to the lack of openscap inputs for other distributions.

### Building the image-scanner image
Inside the git repository is a directory called docker which contains a docker file for RHEL and Fedora, named Dockerfile and Dockerfile.fedora respectively.  To build the Fedora image, simply running the following from the base git directory.

````
sudo docker build -t fedora-image-scanner -f docker/Dockerfile.fedora .
...
Content removed for brevity
Step 9 : CMD /usr/bin/image-scanner-d.py
 ---> Running in 9add596940ac
 ---> 9884820b91c7
Removing intermediate container 9add596940ac
Successfully built 9884820b91c7
````
### Running the image-scanner
The image scanner can be run in two different ways: via commandline or via API.  We believe both ways, the image-scanner should be run within the confines of a container.  Our expectation is that after some time, running the Client API will be the preferred method.  Running the command line method will
be favored for simple, immediate checks.

#### Running the image-scanner as a daemon (default)
The default behavior of the image-scanner image is to run as a REST daemon intended to interact with the client APIs.  Use the atomic command to create and run a container based on the image-scanner image.

First, use atomic to 'install' the image.  This prepares the image to be run by adding /etc/image-scanner/image-scanner.conf file into your filesystem.  This file contains several editable attributes  for running the image-scanner.
````
[bbaude@localhost image-scanner]$ atomic install fedora-image-scanner
docker run --rm -it --privileged -v /etc/:/host/etc/ -e IMAGE=fedora-image-scanner -e NAME=fedora-image-scanner fedora-image-scanner sh /root/image-scanner/docker/image-scanner-install.sh

The image-scanner configuration file is located at /etc/image-scanner/image-scanner.conf with defaults.  You can change the port number and broadcasting IP in that file
````
Now you can run the image-scanner simply with the atomic command:
````
[bbaude@localhost image-scanner]$ atomic run fedora-image-scannerdocker
run -dt --privileged -v /proc/:/hostproc/ -v /sys/fs/cgroup:/sys/fs/cgroup -v /var/log:/var/log -v /tmp:/tmp -v /run:/run -v /var/lib/docker/devicemapper/metadata/:/var/lib/docker/devicemapper/metadata/ -v /dev/:/dev/ -v /etc/image-scanner/:/etc/image-scanner --env container=docker --net=host --cap-add=SYS_ADMIN --ipc=host fedora-image-scanner
acb44b0cb87cbcb94047a0c8e8873dcb451ebb927005afce2e8a77929cacdac2
````

#### Running the image-scanner from the command line inside the container
As mentioned earlier, you can run the image-scanner from the command line.  Firstly, we need the container ID of the image-scanner.

````
[bbaude@localhost image-scanner]$ docker ps
CONTAINER ID        IMAGE                  COMMAND                CREATED             STATUS              PORTS               NAMES
31f34f95915d        fedora-image-scanner   "/bin/sh -c /usr/bin   3 seconds ago       Up 2 seconds                            trusting_kirch
````
With the container ID, you can now use docker exec to 'enter' the container and run the image-scanner on the command line.

````
[bbaude@localhost image-scanner]$ atomic run 31f34f95915d /bin/bash
[image-scanner]#  docker_scanner.py -s bef54

Begin processing


[####################] 100%    1/1


Summary:
     Image: bef54b8f8a2fdd221734f1da404d4c0a7d07ee9169b1443a338ab54236c8c91a
     OS: Red Hat Enterprise Linux Server release 7.0 (Maipo)
     Containers affected (14): 92b40036df6c, 1e30cf43682f, 69f2e0e235bc, 16aa8e002c75, d509243f9f57, 2afb7826ab2e, 2e8aef51d32e, 87a04ca27415, 4fcb771eacf2, 73f0d6d0da09, 06c507ed5d13, b10ace4ded9a, d5d35c53b264, 4f36b909b5ae
     Results: Critical(1) Important(4) Moderate(11) Low(1)

Writing summary and reports to /tmp/openscap_reports
````
#### Running the image-scanner using 'image-scanner-remote'
We also provide a command line utility that allows you to scan both local and remote hosts and it provides a basic summarized response.  The command name is 'image-scanner-remote'.  Run the command with the --help switch to see its syntax.

One very useful part of the image-scanner-remote tool is that it it has a switch where you can choose a profile defined in /etc/image-scanner/image-scanner-client.conf.  This allows you to simply switch from local host to another remote host and so on.  Here is an example of scanning an image on a remote, virtualized host.
````
[bbaude@localhost]$ image-scanner-remote.py --profile localhost -s bef54


Time of Scan:
  2015-06-27 09:08:14.022302
Docker host:
  unix://var/run/docker.sock
Scanned image:
  bef54b8f8a2fdd221734f1da404d4c0a7d07ee9169b1443a338ab54236c8c91a
Base image:
  bef54b8f8a2fdd221734f1da404d4c0a7d07ee9169b1443a338ab54236c8c91a
Containers based on same image:
  92b40036df6cde446374524f3a836e6a9433c310e9996625028c5f47f94f3ecf
  1e30cf43682f90a3c5c337dfc80a5a89713eac84e0dd02e8003297283aa24ca3
  69f2e0e235bcefa424a522d772612f82d927f9b2738e66f867478b1fb3fda431
  16aa8e002c752d7bc6dbc16570266f3e606efa7435f8e8876088ca0156232e7c
  d509243f9f575ae00db336ee9fe23c23cbf5a58a74e8cc1675f43d5c2eeef7ad
  2afb7826ab2e3af1695b2275e9365dd5bd7653f0de74e2a59b61b4adb079abb9
  2e8aef51d32e76ebf9002231110fcbbdd83cb37505cda13b04628a31777f47f2
  87a04ca2741579666ff402ee2b9d116b1c2245c23ea47d98adf5a1095d21a225
  4fcb771eacf273b78bb3eab799441fd7fc7be4202d0fc4e099ed01a2b29a80bf
  73f0d6d0da0941a0803c05668e0ed14f160d6ce774b94b63d81af52c4f22c66b
  06c507ed5d13ec6bc9dd47db739806754359b0f1d6c845e896429de1ffce4eac
  b10ace4ded9a062f0ff8842cea104177bc073e10aa10c691b7546240f0852113
  4f36b909b5ae9f1c352421c412a8070dcc4984baf81255347cf7ce7800bb388d
Susceptible CVEs:
  Critical(1):
     RHSA-2015:0092: glibc security update
  Important(4):
     RHSA-2014:1976: rpm security update
     RHSA-2014:1948: nss, nss-util, and nss-softokn security, bug fix, and enhancement update
     RHSA-2014:1652: openssl security update
     RHSA-2014:1110: glibc security update
  Moderate(12):
     RHSA-2015:1185: nss security update
     RHSA-2015:1115: openssl security update
     RHSA-2015:1072: openssl security update
     RHSA-2015:0749: libxml2 security update
     RHSA-2015:0716: openssl security and bug fix update
     RHSA-2015:0439: krb5 security, bug fix and enhancement update
     RHSA-2015:0327: glibc security and bug fix update
     RHSA-2015:0066: openssl security update
     RHSA-2014:2023: glibc security and bug fix update
     RHSA-2014:1655: libxml2 security update
     RHSA-2014:1052: openssl security update
     RHSA-2014:0687: libtasn1 security update
  Low(1):
     RHSA-2015:0330: pcre security and enhancement update

````

### Client API

The client API is now written in Python and provides several key API calls.

#### Instantiating
When instantiating the Client class, you can provide an IP address or hostname of where the scanning should be done.  You can also provide the port number and the number of parallel processes you want to run.  By default the port will fallback to 5001 and the number of threads will be 2 which is the minimum.
````
from image_scanner_client import Client
image_scanner = Client("foo.bar.org", "5002", "3")
````
#### scan_all_containers
Scan all containers and optionally declare if you want to scan only active containers.  A JSON object is returned.
````
foo =  image_scanner.scan_all_containers(onlyactive=True)
````
#### scan_images
Scan images where scope is defined by an optional 'all' arguement.  When all is True, then it will scan all images including intermediate images (i.e. docker images -a).  Else it will scan a list of images similar to 'docker images'.
````
foo = image_scanner.scan_all_images(all=False)
````
#### scan_list
Scan a list of containers or images.  The list can be container or image names or IDs.  A JSON object is returned.
````
foo = image_scanner.scan_list(['bef54', 'mycontainer', 'ab4523', 'myimage'])
````
#### inspect_container
Similar to docker inspect and requires the container ID as input.  Allows you to obtain the JSON data associated with the container.  Returns a JSON object.
````
foo = image_scanner.inspect_container("container_id")
````
#### inspect_image
Similar to docker inspect and requires the image ID as input.  Allows you to obtain the JSON data associated with the image.  Returns a JSON object.
````
foo = image_scanner.inspect_image("image_id")
````
#### get_xml
Given an URL from a result JSON, obtain the associated openscap result XML.  The return is an ElementTree object.
````
foo = image_scanner.get_xml("url")
````
### XML Parsing API
This set of APIs helps transform the XML-based openscap reports into a form they desire.  It is a Python API as well.

... to be continued

### Building RPMs from the git tree

Once you have a checkout of the git repository, you can easily create RPMs from the git content.

First being by cleaning any clutter from previous builds.
````
[bbaude@localhost image-scanner]$ make clean
rm -fvr packaging/image-scanner-*
rm -fvr packaging/noarch
````
Now issue the make command to build RPMs.
````
[bbaude@localhost image-scanner]$ make -C packaging -f Makefile.dist-packaging rpm
make: Entering directory '/home/bbaude/docker/image-scanner/packaging'
set -x; \
echo "PACKAGE=image-scanner"; \
TARFILE_TMP=image-scanner-0f13ae0.tar.tmp; \
echo "Archiving image-scanner at $(git describe --always --tags)"; \
...
Content Removed for brevity
...
Wrote: /home/bbaude/docker/image-scanner/packaging/noarch/image-scanner-0f13ae0-1.fc21.noarch.rpm
Wrote: /home/bbaude/docker/image-scanner/packaging/noarch/image-scanner-python-client-0f13ae0-1.fc21.noarch.rpm
Executing(%clean): /bin/sh -e /var/tmp/rpm-tmp.VguHeY
+ umask 022
+ cd /home/bbaude/docker/image-scanner/packaging
+ cd image-scanner-0f13ae0
+ /usr/bin/rm -rf /home/bbaude/docker/image-scanner/packaging/.build/image-scanner-0f13ae0-1.fc21.x86_64
+ exit 0
Executing(--clean): /bin/sh -e /var/tmp/rpm-tmp.llRIAd
+ umask 022
+ cd /home/bbaude/docker/image-scanner/packaging
+ rm -rf image-scanner-0f13ae0
+ exit 0
make: Leaving directory '/home/bbaude/docker/image-scanner/packaging'
````
The RPMs will then be stored locally in the packaging/noarch directory.
````
[bbaude@localhost image-scanner]$ ls -l packaging/noarch/
total 80
-rw-r--r--. 1 bbaude users 61304 Jun 22 13:47 image-scanner-0f13ae0-1.fc21.noarch.rpm
-rw-r--r--. 1 bbaude users 20016 Jun 22 13:47 image-scanner-python-client-0f13ae0-1.fc21.noarch.rpm
[bbaude@localhost image-scanner]$

````
