#!/bin/bash



rm /home/abhishek/linux/linux_packages/*.deb
scp -i ~/.ssh/id_rsa rakeshb@10.192.46.20:/mnt/DATA1/rakeshb/drones/*.deb /home/abhishek/linux/linux_packages
cd ~/linux/linux_packages
sudo dpkg -i *.deb
#reboot
