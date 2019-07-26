cd /home/abhishek/Desktop/drones/apparmor-apparmor-2.13/libraries/libapparmor
./autogen.sh
sh ./configure --prefix=/usr --with-perl --with-python
make
#make check
make install

'''
#Binary Utilities:
cd /home/abhishek/linux/apparmor-apparmor-2.13/binutils
make
make check
make install
'''

 #parser:
cd /home/abhishek/Desktop/drones/apparmor-apparmor-2.13/parser
make      # depends on libapparmor having been built first
#make check
make install

'''
#Utilities:

cd /home/abhishek/linux/apparmor-apparmor-2.13/utils
make
make check
make install

#Apache mod_apparmor:

cd /home/abhishek/linux/apparmor-apparmor-2.13/changehat/mod_apparmor
make      # depends on libapparmor having been built first
make install
'''
