cd /mnt/DATA1/rakeshb/drones

rm *.deb
rm *.buildinfo
rm *.changes

cd /mnt/DATA1/rakeshb/drones/linux-5.2.1

make build -j32 bindeb-pkg
