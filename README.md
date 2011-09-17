warcaster
=========

When trying to play Warcraft III via LAN, you may have encountered problems
regarding host discovery. That is, if your computers reside in different
LAN segments, the clients may not see the UDP broadcasts of the server.

Use warcaster to facilitate the discovery of Warcraft III hosts residing
in different LAN segments.

How does it work?
-----------------

warcaster uses libpcap/WinPcap to capture the UDP broadcasts of
a Warcraft III server. For warcaster to _see_ those packets, it should run
in a machine residing in the same LAN segment as the server.

For each captured packet, the destination MAC address is set to one of the
registered clients and is injected back to the wire.

In pseudocode, it looks like this:

    for each packet:
        for each client:
            new_packet = copy(packet)
            new_packet.dst_mac = client.mac
            device.inject(new_packet)

Installation
------------

### Windows

1. Download and install the [WinPcap driver](http://www.winpcap.org/).
2. Download `warcaster.exe`.

### Linux

1. Install gcc and libpcap.
2. `make`

Usage
-----

### Warcraft III server

1. Run warcaster.
2. Select the interface connected to your LAN
3. Start Warcraft III and create a LAN game.

### Warcraft III client

1. ping the server.
2. Start Warcraft III and join the LAN game.
