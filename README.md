# Wireshark dissector for BlackRock Microsystems (R) Cerebus NSPs

## About

In interacting with BlackRock's NSPs, the need arose to take a closer look at the network communication.
NSPs communicate with host PCs over the UDP protocol. This is a simple Lua extension script for Wireshark,
enabling disseciton of network packets.

The dissector is based on `cbhwlib.h` (version 3.10) as published as part of [CereLink](https://github.com/dashesy/CereLink). The current firmware version is `6.05.02` and may be incompatible with other versions.

A subset of commonly observed packets is supported, and not all of them at all detail.

This plugin has been successfully tested on macOS and Windows, with Wireshark version 2.6.2.

## Use

Copy (or link) `Cerebus.lua` in your Wireshark's plugin folder, and restart Wireshark (or reload Lua extensions).
UDP packets containing Cerebus packets should be automatically dissected and information displayed.

In order to use colour definitions, open the menu View → Coloring Rules… and click on 'Import…'. Select the file `Colours` in this folder. Drag new rules to top to make them trigger first.

## Extension

It should be relatively straightforward to extend the dissector for other packet types. Have a look at the packet defintions between the lines

    -- Packet definitions start here

and

    -- Packet definitions end here.

## Version History

- Release 1.0 2017-03-14: First working release.
- 1.1 2017-03-22 Add more channel info fields
- 1.2 2018-08-01 Fix for Wireshark version 2.6.2; fix typos and some fields

## License

The dissector is licensed under the GPLv3. See `LICENSE`.
