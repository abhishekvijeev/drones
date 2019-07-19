cd /mnt/DATA1/rakeshb/drones/
rm *.deb
rm *.changes
rm *.buildinfo
cd /mnt/DATA1/rakeshb/drones/linux-5.1.3/

make -j32 bindeb-pkg
