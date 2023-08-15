import sys
import broker

# Setup endpoint and connect to Zeek.
ep = broker.Endpoint()
sub = ep.make_subscriber("/topic/test")
ss = ep.make_status_subscriber(True);
ep.peer("127.0.0.1", 9999)

#print connection information
st = ss.get()
print(st)

#send ping[0] ping[2] ... to Zeek
#recieve pong[0] pong[2] ... from Zeek
for n in range(5):
    # Send event "ping(n)".
    ping = broker.zeek.Event("ping", n);
    ep.publish("/topic/test", ping);

    # Wait for "pong" reply event.
    (t, d) = sub.get()
    pong = broker.zeek.Event(d)
    print("received {}{}".format(pong.name(), pong.args()))
