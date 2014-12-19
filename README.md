pdp_finder
==========

wireshark extension finds pdp for specified imsi in the pcap/pcapng trace
Wireshark extension which allows to findsignalling (GTP, Gx,Gy, RADIUS) for specific IMSI in the pcap trace which holds multiple pdp sessions. 

To use it you need to to tell Wireshark to load it:
wireshark -X lua_script:pdp_finder_imsi.lua
(It can be done with shortcut in Windows)

When the Wireshark is loaded tool will be in the menu:
Tools-> PDP Finder
It will open a window with parameters:
- IMSI to search
- everything else is script parameters (like ports used for protocols), if you leave it blanc it will be set to defaults (specified in brackets)

Once you hit OK it will go through the trace and add a new protocol field to the packets that match the flow and apply a filter to this field
automatically  (pdp.imsi == <your IMSI>)

To search for new IMSI you need to go to the script menu again and run it again, to remark all packets.

The script has the following limitations:
- It needs to have a start for signalling (like Create PDP request and CCRI) to find the packets properly 
- it is working now only with GTPv1, not with GTPv2 
- it works only for one PDP in time (so no secondary pdp), but any number of subsequent PDPs can be found
- it is looking for IMSI in Subscription-ID for Gx/Gy, so if it is in other AVP it will not work
- if you have your own “Decode As” options specified it might not work ( check Analyse->User Specified Decodes… to be empty)
- it is provided As is and I’m not responsible for any harm or what so ever and blah-blah-blah )
