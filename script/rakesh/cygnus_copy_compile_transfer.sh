#!/bin/bash

#scp -i ~/.ssh/id_rsa -rp ~/linux/linux-5.1.3 rakeshb@10.192.46.64:/mnt/DATA1/rakeshb/linux/

#ssh -i ~/.ssh/id_rsa rakeshb@10.192.46.64 "rm /mnt/DATA1/rakeshb/linux/*.deb"
#ssh -i ~/.ssh/id_rsa rakeshb@10.192.46.64 "rm /mnt/DATA1/rakeshb/linux/*.changes"
#ssh -i ~/.ssh/id_rsa rakeshb@10.192.46.64 "rm /mnt/DATA1/rakeshb/linux/*.buildinfo"
#ssh -i ~/.ssh/id_rsa rakeshb@10.192.46.64 "cd /mnt/DATA1/rakeshb/linux/linux-5.1.3/ && make -j72 bindeb-pkg"



rm /home/abhishek/linux/linux_packages/*.deb
scp -i ~/.ssh/id_rsa abhishek@10.192.46.64:/home/abhishek/linux/*.deb /home/abhishek/linux/linux_packages
cd ~/linux/linux_packages
sudo dpkg -i *.deb
#reboot
