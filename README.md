ICEtunnel
===============

ICEtunnel is a tool for tunneling a UDP (or TCP) connection inside a ICE UDP session, in order to get peer-to-peer connectivity
using ICE NAT-traversal features.
Using ICEtunnel you can get a peer-to-peer connection between two peers, even if they are both behind a NAT.

ICE works in quite any case, except when one of the two networks does not permit UDP traffic, or both networks are
symmetic-NATs (quite usual just for some enterprise-level NAT).

Requirements
===============
* Library libpjproject ( http://www.pjsip.org/ ). I remind you to use ./configure -prefix /usr if you compile it from sources.
* pkg-config

How to install
===============
 $ make
 
How to use - Quick start
===============
For the offerer:
 $ ./icetunnel -s stunserver.org
 
For the answerer:
 $ ./icetunnel -s stunserver.org -a
 
 
* After starting run the following command on both peers:

 $ nc 127.0.0.1 7001

* Copy the informations until the last line on one peer and paste to the other peer nc session, and vice versa
* End the data paste using a double-newline on both peers at the same time

* On the answerer:

 Start a UDP server on port 7003 (for example nc -u -l 7003)

* On the offerer:

 Start a UDP client to 127.0.0.1:7002 (for example nc -u 127.0.0.1 7002)


 
