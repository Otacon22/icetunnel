ICE-experiments
===============

Some experiment did using the ICE functions of libpjproject 

Requirements
===============
* Library libpjproject ( http://www.pjsip.org/ )

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

 Start a UDP server on port 7003

* On the offerer:

 Start a UDP client to 127.0.0.1:7002


 
