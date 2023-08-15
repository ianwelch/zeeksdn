event NetControl::init() {
    #start the NetControl backend
    local debug_plugin = NetControl::create_debug(T);
    NetControl::activate(debug_plugin, 0);
}

event connection_established(c: connection) {
    #c is the incoming connection data structure
    #drop_connection drops the connection given by id for a time period
    #so for every incoming connection, we pass the connection id to 
    #netcontrol and drop the connection for 20 seconds
    NetControl::drop_connection(c$id, 20 secs);
}
