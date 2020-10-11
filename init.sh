source devices.env

SDK=~/Simplicity/latest/developer/sdks/blemesh/v1.7
#cp ${SDK}/app/bluetooth/appbuilder/sample-apps-bin/soc-btmesh-empty-brd4104a-gcc.hex image.hex
cp soc-btmesh-empty/GNU*/*.hex image.hex

for sn in ${SNS_BRD4104A}
do
    #commander device masserase -s ${sn}
    commander flash image.hex -s ${sn}
done

rm image.hex
