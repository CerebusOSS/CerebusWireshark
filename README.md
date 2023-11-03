# Wireshark dissector for BlackRock Microsystems (R) Cerebus NSPs

## About

In interacting with BlackRock's NSPs, the need arose to take a closer look at the network communication.
NSPs communicate with host PCs over the UDP protocol. This is a simple Lua extension script for Wireshark,
enabling dissection of network packets.

The dissector is based on Blackrock's protocol specifications published as part of [CereLink](https://github.com/CerebusOSS/CereLink).
The relevant file was `cbhwlib.h` for embedded software versions 6.x and 7.0.x, and is now `cbproto.h` in 7.5, 7.6, and above.

Embedded software versions map to protocol version as follows:

* 6.0.5 :: 3.10 (no longer supported with a lua script)
* 7.0.x :: 3.11
* 7.5 :: 4.0 (very limited release, please upgrade!)
* 7.6 :: 4.1

## Use

Copy (or link) one of the `Cerebus<proto version>.lua` scripts into your Wireshark's plugin folder, and restart Wireshark (or reload Lua extensions).
UDP packets containing Cerebus packets should be automatically dissected and information displayed.

In order to use colour definitions, open the menu View → Coloring Rules… and click on 'Import…'. Select the file `Colours` in this folder. Drag new rules to top to make them trigger first.

For users of the Gemini family of systems, on protocols 4.1 and above, you may want to set your Wireshark filter to select packets from a single device: `udp.port==<port number>`, where port number is:

* Gemini NSP :: 51001
* Gemini Hub1 :: 51002
* Gemini Hub2 :: 51003

## License

The dissector is licensed under the GPLv3. See `LICENSE`.
