"""
define a network of 3 hosts and integrate with an external ryu controller
author: Ben Cravens
"""
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSController

class single_switch_topo(Topo):
    "build single switch topology"
    def build(self, n=3):
        #add switch
        switch = self.addSwitch('s1')
        #add hosts
        for i in range(n):
            host_str="h{}".format(i+1)
            host = self.addHost(host_str)
            self.addLink(host,switch)

class ryu_net():
    "uses single switch topology to build a network controlled by external ryu SND controller"
    def __init__(self, hostnum=3):
        #build our network
        self.topo=single_switch_topo(hostnum)
        self.net = Mininet(topo=self.topo, controller=None)
        #connect controller
        self.connect_ryu()
        self.net.start()
        #run a couple of pings to show the switch learning the route..
        #the first ping will be slow, subsequent pings will be fast.
        h1 = self.net.get('h1')
        h2 = self.net.get('h2')
        h3 = self.net.get('h3')
        hosts=[h1,h2,h3]
        print(h1.cmd('ping -c 3', h2.IP()))
        print(h2.cmd('ping -c 3', h3.IP()))
        print(h3.cmd('ping -c 3', h1.IP()))
        #run mininet command line interface
        CLI(self.net)
        
    def disconnect(self):
        #stop network
        self.net.stop()

    def connect_ryu(self):
        #connect to external ryu controller..
        self.net.addController('co', controller=RemoteController, ip='127.0.0.1', port=6633)                                                   

if __name__=="__main__":
    my_net = ryu_net()
    my_net.disconnect()
