# Client API

The client API is now written in Python and provides several key API calls.

## Instantiating
When instantiating the Client class, you can provide an IP address or hostname of where the scanning should be done.  You can also provide the port number and the number of parallel processes you want to run.  By default the port will fallback to 5001 and the number of threads will be 2 which is the minimum.
````
from image_scanner_client import Client
image_scanner = Client("foo.bar.org", "5002", "3")
````
## scan_all_containers
Scan all containers and optionally declare if you want to scan only active containers.  A JSON object is returned.
````
foo =  image_scanner.scan_all_containers(onlyactive=True)
````
## scan_images
Scan images where scope is defined by an optional 'all' arguement.  When all is True, then it will scan all images including intermediate images (i.e. docker images -a).  Else it will scan a list of images similar to 'docker images'.
````
foo = image_scanner.scan_all_images(all=False)
````
## scan_list
Scan a list of containers or images.  The list can be container or image names or IDs.  A JSON object is returned.
````
foo = image_scanner.scan_list(['bef54', 'mycontainer', 'ab4523', 'myimage'])
````
## inspect_container
Similar to docker inspect and requires the container ID as input.  Allows you to obtain the JSON data associated with the container.  Returns a JSON object.
````
foo = image_scanner.inspect_container("container_id")
````
## inspect_image
Similar to docker inspect and requires the image ID as input.  Allows you to obtain the JSON data associated with the image.  Returns a JSON object.
````
foo = image_scanner.inspect_image("image_id")
````
## get_xml
Given an URL from a result JSON, obtain the associated openscap result XML.  The return is an ElementTree object.
````
foo = image_scanner.get_xml("url")
````

# Scanning multiple remote hosts
You can also use the API to scan multiple hosts and get a single data object back.  The data object is a makeup of the same data for a single scan; however, each remote host is in it. The APIs for scanning multiple hosts are in a different class.

## Instantiating
The main APIs for multiple host scanning can be found in the ClientCommon class.  It has one optional arguement which should be True or False depending on whether you are using the class as an API (True) or in something like a command line utility.  If you do not define the optional arguement, the 'api' value will default to True.
````
multi_scan = ClientCommon(api=False)
````
## Scan multiple remote hosts
You can scan multiple remote hosts with the scan_multiple_hosts API.

````
multi_scan.scan_multiple_hosts(profile_list, onlyactive=True, remote_threads=4)
````
The profile_list argument needs to be a list of profiles from /etc/image-scanner/image-scanner-client.conf.

One of the scan types (allimages, images, allcontainers, or onlyactive) must be set to True.  

The remote_threads argument is an optional argument that defines the number of simultaneous remote scans you want to initiate. The return is a summary of the scan.

## Obtaining a list of profile names
The scan_multiple_hosts API requires a list of profile names as input.  If you are wanting to scan all the profiles defined in /etc/image-scanner/image-scanner-client.conf you can use the get_all_profile_names API.

````
all_profiles = multi_scan.get_all_profile_names()
````

You can now pass all_profiles to the scan_multiple_hosts API.

## Debugging
There is a handy API provided for printing json values while writing code.

````
multi_scan.debug_json(json_object)
````

# XML Parsing API
This set of APIs helps transform the XML-based openscap reports into a form they desire.  It is a Python API as well.

## get_cve_info
This is a 'wrapper' function that takes a docker_state.json pointer (can be either a path or URL) and returns a list of tuples with the CVE information in them.

````
foo = xmlp.get_cve_info("http://localhost:5001/reports/docker_state.json")
````
## summary
Given a docker_state.json URL or path, creates and prints a summary report based on the scan.  The report is by image or container that was scanned.
