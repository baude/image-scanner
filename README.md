# image-scanner

### About

The image-scanner is a multi-faceted scanner for CVEs in containers and images.  Upon scanning a container or image, it then produces a report of any vulnerabilities found.  The image-scanner uses openscap to determine any vulnerabilities.

The image-scanner can be run on the command line but it is designed to be driven by a Python client API via REST.  In fact, our primary use case is for it to be run as "middleware" where using provided APIs, the consumer can take the common output data and transform it into something useful for their environment or application.  The image-scanner can also run parallel scans to speed up results.

As of this writing, the image-scanner can only scan Red Hat Enterprise based containers and images due to the lack of openscap inputs for other distributions.

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
#### scan_all_images
Scan all images and return a JSON object.
````
foo = image_scanner.scan_all_images()
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
