#! /bin/sh -e

IMAGE_DIR="/host/etc/image-scanner"
IMAGE_CONF="image-scanner.conf"

if [ ! -d ${IMAGE_DIR} ]; then
  echo "Creating directory /etc/image-scanner"
  mkdir ${IMAGE_DIR}
else
  if [ -d ${IMAGE_DIR}/${IMAGE_CONF} ]; then
      echo "Backing up previous configuration file"
      mv ${IMAGE_DIR}/${IMAGE_CONF} ${IMAGE_DIR}/${IMAGE_CONF}.bak
  fi
fi

printf "\nThe image-scanner configuration file is located at /etc/image-scanner/image-scanner.conf with defaults.  You can change the port number and broadcasting IP in that file\n"
cp /root/image-scanner/conf/${IMAGE_CONF} ${IMAGE_DIR}/

