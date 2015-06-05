import requests
import json

api_path = "image-scanner/api"
headers = {'content-type': 'application/json'}
host = "localhost"
port = 5001
api_func = "scan"

# Replace with an example of an image id
image_ids = ['bef54', '10acc']
my_input = {'images': image_ids, 'number': 4}

my_url = "http://{0}:{1}/{2}/{3}".format(host, port, api_path, api_func)

my_session = requests.Session()
my_session.get(
my_return = my_session.get(my_url, data=json.dumps(my_input), headers=headers)

print my_return.text
