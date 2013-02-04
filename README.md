ICE-experiments
===============

Some experiment did using the ICE functions of libpjproject 

Requirements
===============
libpjproject ( http://www.pjsip.org/ )

How to install
===============
 $ make
 
How to use
===============
For the offerer:
 $ ./icetunnel -s stunserver.org
For the answerer:
 $ ./icetunnel -s stunserver.org -a
