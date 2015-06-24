from setuptools import setup, find_packages

setup(name='image-scanner',
      version='0.1a',
      description='Vulnerability scanner for containers and images',
      author='Brent Baude',
      author_email='bbaude@redhat.com',
      url='https://github.com/baude/image-scanner',
      license='LGPLv2+',
      #packages=find_packages(),
      packages=['image_scanner', 'image_scanner_client'],
      scripts=['image_scanner/image-scanner-d.py',
               'image_scanner/docker_scanner.py',
               'image_scanner_client/image-scanner-remote.py'],
      py_modules=['image_scanner/rest',
                  'image_scanner/applicationconfiguration',
                  'image_scanner/dist_breakup',
                  'image_scanner_client/image_scanner_client',
                  'image_scanner/reporter',
                  'image_scanner/scan',
                  'image_scanner/xml_parse',
                  'image_scanner/image_scanner']
)
