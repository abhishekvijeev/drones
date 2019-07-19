#!/bin/bash



rm /home/abhishek/linux/linux_packages/*.deb
scp -i ~/.ssh/id_rsa abhishek@10.192.46.64:/home/abhishek/drones/*.deb /home/abhishek/linux/linux_packages
cd ~/linux/linux_packages
sudo dpkg -i *.deb
#reboot
