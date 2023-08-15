# load extra zeek scripts we need using @load
# frameworks are stored on github at https://github.com/zeek/zeek/tree/master/scripts/base/frameworks
# you can look there for more information. 
# Note some plugins are included via the frameworks, i.e openflow includes broker scripts
# Thus you can find broker info in https://github.com/zeek/zeek/tree/master/scripts/base/frameworks/openflow/plugins
# conn gives support for connection (TCP etc) analysis
@load base/protocols/conn
# openflow framework allows us to work with openflow capable external hardware
@load base/frameworks/openflow
# netcontrol framework enables interaction with networking hardware/software
@load base/frameworks/netcontrol

# &redef allows us to redefine initial values of global variables
# here we set the port zeek uses to talk to the ryu controller via broker
# to be 9999, and we use the TCP protocol.
const broker_port: port = 9999/tcp &redef;
# define our openflow controller object globally
global of_controller: OpenFlow::Controller;

# Switch datapath ID.
# A datapath ID uniquely identifies an openflow enabled switch.
const switch_dpid: count = 12 &redef;
# port on which Zeek is listening - we install a rule to the switch to mirror traffic here...
const switch_bro_port: count = 19 &redef;

# In zeek, an event handler has the following syntax:
#
# event MyFramework::myevent() {
# 	print "Event myevent defined in plugin MyFramework has happened!";
#	print "Do some stuff!";
# }

# Syntax: Netcontrol::init() runs when NetControl boots up
# This initialises plugins/backends which netcontrol needs to communicate rules & changes with devices.
# &priority=2 sets this event to execute first.
event NetControl::init() &priority=2
	{
	
	## OpenFlow::broker_new is the Broker controller constructor method.
	## host: Controller ip.
	## host_port: Controller listen port.
	## topic: Broker topic to send messages to.
	## dpid: OpenFlow switch datapath id.
	## Returns: OpenFlow::Controller record.
	## A record is just like a struct in C.
	## global broker_new: function(name: string, host: addr, host_port: port, topic: string, dpid: count): OpenFlow::Controller;
	
	of_controller = OpenFlow::broker_new("of", 127.0.0.1, broker_port, "bro/openflow", switch_dpid);

	## NetControl::create_openflow instantiates an openflow plugin for the NetControl framework.
	## NetControl::OfConfig specifies the configuration record (struct) that is passed to create_openflow.
	## $monitor=T  -> Accept rules that target the monitor path.
	## $forward=F  -> Reject rules that target the forward path.
	## $priority_offset+=5 -> Add 5 to all rule priorities.
	local pacf_of = NetControl::create_openflow(of_controller, NetControl::OfConfig($monitor=T, $forward=F, $priority_offset=+5));
	
	#Activate our plugin so we can use it. Priority 0 (neutral)
	NetControl::activate(pacf_of, 0);
	}

# A Broker peer has been added. Let's print out network level information 
# of the endpoint we have peered with.
event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "Broker peer added", endpoint$network;
	}
	
# This event is triggered when initialization is completed.
# We will now start 
event NetControl::init_done()
	{
	print "NeControl is starting operations";
	## Clear the current flow table of the controller.
	OpenFlow::flow_clear(of_controller);
	## global flow_mod: function(controller: Controller, match: ofp_match, flow_mod: ofp_flow_mod): bool;
	## Global flow_mod function.
	## controller: The controller which should execute the flow modification.
	## match: The ofp_match record which describes the flow to match.
	## flow_mod: The openflow flow_mod record which describes the action to take.
	## Here our target controller is of_controller 
	## Our match is null (applies to all)
	## Action: adds a flow to route a copy of all the traffic coming into our openflow switch to our zeek instance via 
	## the port on which Zeek is listening.
	OpenFlow::flow_mod(of_controller, [], [$cookie=OpenFlow::generate_cookie(1337), $priority=2, $command=OpenFlow::OFPFC_ADD, $actions=[$out_ports=vector(switch_bro_port)]]);
	}

## --------------------------------
## Boilerplate code section
## This section contains code that mostly just provides information about what Zeek
## Is doing while it is running NetControl.
## --------------------------------

## rule_added:
## Confirms that a rule was put in place by a plugin.
## r: The rule now in place. This has a unique id string that can be called with r$id
## p: The state for the plugin that put it into place.
## msg: An optional informational message by the plugin.
event NetControl::rule_added(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
	{
	# When a rule is added, confirm it, then print the id of the rule.
	print "Rule added successfully", r$id;
	}

## rule_error:
## Reports an error when operating on a rule.
## r: The rule that encountered an error.
## p: The state for the plugin that reported the error.
## msg: An optional informational message by the plugin.
event NetControl::rule_error(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
	{
	print "Rule error", r$id, msg;
	}

## rule_timeout:
## Reports that a rule was removed from a plugin due to a timeout.
## r: The rule now removed.
## i: Additional flow information, if supported by the protocol.
## p: The state for the plugin that had the rule in place and now
##    removed it.
## msg: An optional informational message by the plugin.
event NetControl::rule_timeout(r: NetControl::Rule, i: NetControl::FlowInfo, p: NetControl::PluginState)
	{
	print "Rule timeout", r$id, i;
	}

## Event confirming successful modification of a flow rule.
## name: The unique name of the OpenFlow controller from which this event originated.
## match: The ofp_match record which describes the flow to match.
## flow_mod: The openflow flow_mod record which describes the action to take.
## msg: An optional informational message by the plugin.
event OpenFlow::flow_mod_success(name: string, match: OpenFlow::ofp_match, flow_mod: OpenFlow::ofp_flow_mod, msg: string)
	{
	#print "Flow mod success";
	}

## Reports an error while installing a flow Rule.
## name: The unique name of the OpenFlow controller from which this event originated.
## match: The ofp_match record which describes the flow to match.
## flow_mod: The openflow flow_mod record which describes the action to take.
## msg: Message to describe the event.
event OpenFlow::flow_mod_failure(name: string, match: OpenFlow::ofp_match, flow_mod: OpenFlow::ofp_flow_mod, msg: string)
	{
	# From https://mailman.stanford.edu/pipermail/openflow-discuss/2010-August/001288.html
	# "The idea behind the cookie is that the controller can essentially give an identifier to a flow entry, 
	# that it can then easily map back to the internal state associated with it."
	# prints said cookie
	print "Flow mod failure", flow_mod$cookie, msg;
	}

## Reports that a flow was removed by the switch because of either the hard or the idle timeout.
## This message is only generated by controllers that indicate that they support flow removal
## in supports_flow_removed.
## name: The unique name of the OpenFlow controller from which this event originated.
## match: The ofp_match record which was used to create the flow.
## cookie: The cookie that was specified when creating the flow.
## priority: The priority that was specified when creating the flow.
## reason: The reason for flow removal (OFPRR_*).
## duration_sec: Duration of the flow in seconds.
## packet_count: Packet count of the flow.
## byte_count: Byte count of the flow.
event OpenFlow::flow_removed(name: string, match: OpenFlow::ofp_match, cookie: count, priority: count, reason: count, duration_sec: count, idle_timeout: count, packet_count: count, byte_count: count)
	{
	print "Flow removed", match;
	}

## --------------------------------
## END Boilerplate code section
## The next section contains code to shunt (drop for a period) incoming connections
## --------------------------------


# Shunt all ssl connections after we cannot get any data from them anymore
## Stops forwarding a uni-directional flow's packets to Zeek.
## f: The flow to shunt.
## t: How long to leave the shunt in place, with 0 being indefinitely.
## location: An optional string describing where the shunt was triggered.
## Returns: The id of the inserted rule on success and zero on failure.
## global shunt_flow: function(f: flow_id, t: interval, location: string &default="") : string;
event ssl_established(c: connection)
	{
	# This event is activate when an SSL (Secure Socket Layer) connection is established.
	# convinience variable to access the id data structure of the connection data structure
	# connection data structure is a nested data structure used to track state on a connection over its lifetime.
	# access the id data field from the connection data structure using the $ field delimiter
	local id = c$id;
	# id data structure:
	# orig_h: The originator’s IP address.
	# orig_p: The originator’s port number.
	# resp_h: The responder’s IP address.
	# resp_p: The responder’s port number.
	# So we are shunting the flow
	# (no longer forwarding the packets to zeek) 
	# coming from (origin ip, origin port) ---> (resp ip, resp port)
	# for 30 seconds by making a flow mod 
	# adding a rule that drops such connections
	NetControl::shunt_flow([$src_h=id$orig_h, $src_p=id$orig_p, $dst_h=id$resp_h, $dst_p=id$resp_p], 30sec);
	}
	
event connection_established(c: connection) 
	{
	print("dropping connections from host h1");
	#drop connections from one specific address
	#local badip = 10.10.10.10;
	#drop it
	#NetControl::drop_connection(badip,0);
	}
