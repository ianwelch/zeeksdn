<h1> Git issue describing problems with package </h1>
<a href="https://github.com/zeek/zeek-netcontrol/issues/11"> Taken from this issue I made </a>

Hi, I am testing controller.py and example.zeek in /openflow. Apologies if this is a silly question as I am new to Zeek.

My goal is to have a simple virtual network defined in mininet with an openflow switch. I would then like to connect this switch to the ryu controller, which is in turn connected to the Zeek instance. The goal is to monitor traffic with Zeek and then modify the switch table to quarantine malicious hosts.

First I define a simple network topology and connect to the ryu controller.

```console
>>> ryu-manager --verbose controller.py
>>> sudo mn --controller=remote,port=6633 --topo=single,3 --switch=ovsk,protocols=OpenFlow13 --mac
```

I think the controller connects to the switch because I get the following message in ryu:

```console
connected socket:<eventlet.greenio.base.GreenSocket object at 0x7f9e1ed38e50> address:('127.0.0.1', 56088)
hello ev <ryu.controller.ofp_event.EventOFPHello object at 0x7f9e1ed45ac0>
move onto config mode
EVENT ofp_event->dpset EventOFPSwitchFeatures
EVENT ofp_event->BroController EventOFPSwitchFeatures
EVENT ofp_event->ofctl_service EventOFPSwitchFeatures
switch features ev version=0x4,msg_type=0x6,msg_len=0x20,xid=0x14ef4d91,OFPSwitchFeatures(auxiliary_id=0,capabilities=79,datapath_id=1,n_buffers=0,n_tables=254)
add dpid 1 datapath <ryu.controller.controller.Datapath object at 0x7f9e1ed45160> new_info <ryu.app.ofctl.service._SwitchInfo object at 0x7f9e1ed45e80> old_info None
move onto main mode
EVENT ofp_event->dpset EventOFPStateChange
DPSET: register datapath <ryu.controller.controller.Datapath object at 0x7f9e1ed45160>
```

If I try to pingall to test the hosts in mininet, it fails, dropping all the packets.
```console
>>> mininet> pingall
*** Results: 100% dropped. (0/6 received).
```

Then, if I try to run the zeek instance, it connects to the ryu controller, but in the process the controller crashes.

```console
>>> zeek example.zeek
Broker peer added, [address=127.0.0.1, bound_port=9999/tcp]
NeControl is starting operations
```

Ryu controller output:
``` console
Got broker status message
Incoming connection established.
Waiting for broker message
Got broker message
flow_clear for OpenFlow::BROKERof 1
EVENT BroController->ofctl_service GetDatapathRequest
EVENT BroController->ofctl_service GetDatapathRequest
Sending message with xid(14ef4d93) to datapath(0000000000000001): version=None,msg_type=None,msg_len=None,xid=0x14ef4d93,OFPFlowMod(buffer_id=4294967295,command=3,cookie=0,cookie_mask=0,flags=0,hard_timeout=0,idle_timeout=0,instructions=[],match=OFPMatch(oxm_fields={}),out_group=4294967295,out_port=4294967295,priority=0,table_id=255)
EVENT BroController->ofctl_service SendMsgRequest
ofctl_service: Exception occurred during handler processing. Backtrace from offending handler [_handle_send_msg] servicing event [SendMsgRequest] follows.
Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/ryu/base/app_manager.py", line 290, in _event_loop
    handler(ev)
  File "/usr/lib/python3/dist-packages/ryu/app/ofctl/service.py", line 150, in _handle_send_msg
    datapath.set_xid(msg)
  File "/usr/lib/python3/dist-packages/ryu/controller/controller.py", line 416, in set_xid
    msg.set_xid(self.xid)
  File "/usr/lib/python3/dist-packages/ryu/ofproto/ofproto_parser.py", line 224, in set_xid
    assert self.xid is None
AssertionError
```

Thanks in advance for the help!
