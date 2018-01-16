#!/bin/bash
#echo \# make sure to edit this deployment script according to your needs
#echo \# e.g. the IP address of the server and the rsync command have to
#echo \# be adjusted
#exit 0

mkdir -p mirror0-files
cd ./raidpir/

while true
do
  # rsync -r server:/path/to/pirchat/storage/pir/ files/
  rsync -r ../storage/pir/ ../mirror0-files/
  ./raidpir_mirror.py --files ../mirror0-files/ --port 8902 --precompute --retrievemanifestfrom 127.0.0.1:8901
  if [ $? -ne 0 ]
  then
    exit
  fi
done
