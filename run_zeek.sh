prefix='/usr/local/zeek'
pcapdir='/share/btest/data/pcaps/tls/ecdhe.pcap'
echo "executing zeek -C -r $prefix$pcapdir test.zeek"
echo "using premade packet capture (pcap) file from dir $pcapdir"
zeek -C -r $prefix$pcapdir test.zeek
cat netcontrol.log
