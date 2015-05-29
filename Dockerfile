FROM registry.access.redhat.com/rhel7:latest

RUN yum -y --disablerepo=\* --enablerepo=rhel-7-server-rpms install yum-utils &&   yum-config-manager --disable \* &&   yum-config-manager --enable rhel-7-server-rpms &&   yum-config-manager --enable rhel-7-server-extras-rpms && yum clean all

RUN yum -y update && yum clean all

# Debug only
RUN yum -y install vim strace file less top

RUN yum -y install docker python-docker openscap-scanner tar


LABEL Version=1.0
LABEL Vendor="Red Hat" License=GPLv3


LABEL RUN="docker run --rm -it --privileged -v /proc/:/hostproc/ -v /sys/fs/cgroup:/sys/fs/cgroup  -v /var/log:/var/log -v /tmp:/tmp -v /run:/run -v /var/lib/docker/devicemapper/metadata/:/var/lib/docker/devicemapper/metadata/ -v /dev/:/dev/ --env container=docker --net=host --cap-add=SYS_ADMIN --ipc=host IMAGE"

ADD image-scanner.py /usr/bin/image-scanner
RUN chmod a+x /usr/bin/image-scanner
ADD dist_breakup.py /usr/bin/

RUN echo 'PS1="[image-scanner]#  "' > /etc/profile.d/ps1.sh

CMD /bin/bash
