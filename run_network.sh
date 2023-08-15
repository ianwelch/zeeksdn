echo 'Linking ryu controller to mininet virtual network.'
echo 'Input controller location'
read con_loc
echo "Running ryu controller $con_loc"

echo "starting ryu controller"
# run ryu controller
ryu-manager $con_loc &

echo "starting mininet in background. To interact with mininet rerun this command in another tab before you run ryu."
# run mininet controller
sudo mn --controller=remote --topo=single,3 --switch=ovsk,protocols=OpenFlow10 --mac &
