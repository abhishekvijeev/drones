#!/bin/bash

ssh -i ~/.ssh/id_rsa abhishek@10.192.46.64 "rm -r /home/abhishek/linux/linux-5.1.3/security/apparmor/*"
scp -i ~/.ssh/id_rsa -rp ~/linux/linux-5.1.3/security/apparmor/* abhishek@10.192.46.64:/home/abhishek/linux/linux-5.1.3/security/apparmor/
scp -i ~/.ssh/id_rsa -rp ~/linux/linux-5.1.3/net/* abhishek@10.192.46.64:/home/abhishek/linux/linux-5.1.3/net/
scp -i ~/.ssh/id_rsa -rp ~/linux/linux-5.1.3/include/linux/* abhishek@10.192.46.64:/home/abhishek/linux/linux-5.1.3/include/linux/
scp -i ~/.ssh/id_rsa -rp ~/linux/linux-5.1.3/init/main.c abhishek@10.192.46.64:/home/abhishek/linux/linux-5.1.3/init/main.c

ssh -i ~/.ssh/id_rsa abhishek@10.192.46.64 "rm /home/abhishek/linux/*.deb"
ssh -i ~/.ssh/id_rsa abhishek@10.192.46.64 "rm /home/abhishek/linux/*.changes"
ssh -i ~/.ssh/id_rsa abhishek@10.192.46.64 "rm /home/abhishek/linux/*.buildinfo"
#ssh -i ~/.ssh/id_rsa abhishek@10.192.46.64 "cd /mnt/DATA1/rakeshb/linux/linux-5.1.3/ && make -j72 bindeb-pkg"



#rm /home/rakesh/linux/linux_packages/*.deb
#scp -i ~/.ssh/id_rsa rakeshb@10.192.46.64:/mnt/DATA1/rakeshb/linux/*.deb /home/abhishek/linux/linux_packages
#cd ~/linux/linux_packages
#sudo dpkg -i *.deb
#reboot
