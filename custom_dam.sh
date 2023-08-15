#!/bin/bash

echo "generate_gNMI_certs"

mkdir -p tls_cert_key
mkdir -p tls_cert_key/server
openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout tls_cert_key/server/server.key -out tls_cert_key/server/server.crt  -subj '/CN=faucet.localhost'
mkdir -p tls_cert_key/client
openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout tls_cert_key/client/client.key -out tls_cert_key/client/client.crt  -subj '/CN=zeek.localhost'
cp tls_cert_key/server/server.crt tls_cert_key/client/ca.crt

#echo "2- OR create and attach to all container at once using xterm"
echo "cr_all_conts_with_xterms"
xterm -T faucet -e  \
                docker run \
                --rm --name faucet \
                -v /var/log/faucet/:/var/log/faucet/ \
                -v $PWD/etc/faucet/faucet.yaml:/etc/faucet/faucet.yaml \
                -v $PWD/tls_cert_key/:/pegler/tls_cert_key/ \
                -p 6653:6653 -p 9302:9302 \
                shaboti/faucet-agent  	&
        
xterm -bg MediumPurple4 -T host -e \
                docker run \
                --rm  --name host \
                -it \
                python bash -c "echo 'RUN: wget http://192.168.0.1:8000' && bash" &

xterm -bg NavyBlue -T server -e \
                docker run \
                --rm --name server \
                -it \
                python bash -c "echo 'RUN: python -m http.server 8000' && bash" &

xterm -bg Maroon -T zeek -e \
                docker run \
                --rm  --name zeek \
                -it \
                -v $PWD/src/:/pegler/src/ \
                -v $PWD/etc/faucet/faucet.zeek.yaml:/pegler/etc/faucet/faucet.zeek.yaml \
                -v $PWD/tls_cert_key/:/pegler/tls_cert_key/ \
                -w /pegler/src \
            shaboti/zeek-ids /bin/bash &


echo "create_ovs_net"
ovs-vsctl add-br ovs-br0 \
-- set bridge ovs-br0 other-config:datapath-id=0000000000000001 \
-- set bridge ovs-br0 other-config:disable-in-band=true \
-- set bridge ovs-br0 fail_mode=secure \
-- set-controller ovs-br0 tcp:127.0.0.1:6653 tcp:127.0.0.1:6654

# create bridge btween zeek and faucet
docker network create --subnet 192.168.100.0/24 --driver bridge zeek_faucet_nw 1>/dev/null
docker network connect --ip 192.168.100.2 zeek_faucet_nw zeek 
docker network connect --ip 192.168.100.3 zeek_faucet_nw faucet

# connect the rest to ovs-br0
ip addr add dev ovs-br0 192.168.0.254/24
ovs-docker add-port ovs-br0 eth1 server --ipaddress=192.168.0.1/24
ovs-docker add-port ovs-br0 eth1 host --ipaddress=192.168.0.2/24
ovs-docker add-port ovs-br0 eth2 zeek --ipaddress=192.168.0.100/24
