-- cb protocol

-- Human readble package type descriptions
local pconftypes = {
        [0x00] = "System Heartbeat",
		[0x01] = "Protocol monitoring packet",
        [0x5c] = "nPlay configuration response",
        [0xdc] = "nPlay configuration request",
        [0x5e] = "nPlay trigger response",
        [0xde] = "nPlay trigger request",
		[0x5f] = "video tracking event",
		[0xdf] = "video tracking request",
		[0x63] = "log event response",
		[0xe3] = "log event request"
}
-- package type as cbhwlib constant names
local pconftypeshwlib = {
        [0x00] = "cbPKTTYPE_SYSHEARTBEAT",
		[0x01] = "cbPKTTYPE_SYSPROTOCOLMONITOR",
        [0x5c] = "cbPKTTYPE_NPLAYREP",
        [0xdc] = "cbPKTTYPE_NPLAYSET",
        [0x5e] = "cbPKTTYPE_TRIGGERREP",
        [0xde] = "cbPKTTYPE_TRIGGERSET",
		[0x5f] = "cbPKTTYPE_VIDEOTRACKREP",
		[0xdf] = "cbPKTTYPE_VIDEOTRACKSET",
		[0x63] = "cbPKTTYPE_LOGREP",
		[0xe3] = "cbPKTTYPE_LOGSET"
}

-- declare our protocol
local cb_proto = Proto("Cerebus","Cerebus NSP Communication")
local f = cb_proto.fields
f.f_tstamp = ProtoField.uint32("Cerebus.TStamp", "Timestamp", base.HEX_DEC)
f.f_chid = ProtoField.uint16("Cerebus.ChannelId","Channel Id",base.HEX_DEC)
f.f_pkttype = ProtoField.uint8("Cerebus.PktType","Packet Type",base.HEX_DEC, pconftypes)
f.f_pkttypehwlib = ProtoField.uint8("Cerebus.PktTypeHW", "Packet type as const", base.HEX_DEC, pconftypeshwlib)

f.f_dlen= ProtoField.uint8("Cerebus.DLen","Data length",base.HEX_DEC)
f.f_data = ProtoField.bytes("Cerebus.Data","Data")


-- create a function to dissect it
function cb_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = cb_proto.name
    local subtree = tree:add(cb_proto, buffer(), "Cerebus Protocol Data")
	subtree:add_le(f.f_tstamp, buffer(0,4))

	--    subtree:add_le(buffer(0,4),"Timestamp: " .. buffer(0,4):le_uint())
	subtree:add_le(f.f_chid, buffer(4,2))
	if buffer(4,2):le_uint() == 0x8000 then
		subtree:add_le(f.f_pkttype, buffer(6,1)):add_le(f.f_pkttypehwlib, buffer(6,1))
	end
	subtree:add_le(f.f_dlen, buffer(7,1))
	subtree:add(f.f_data, buffer(8, buffer(7,1):uint() * 4))
--	subtree:add(buffer(6,1),"Packet type: " .. buffer(6,1):uint())
    -- subtree = subtree:add(buffer(2,2),"The next two bytes")
    -- subtree:add(buffer(2,1),"The 3rd byte: " .. buffer(2,1):uint())
    -- subtree:add(buffer(3,1),"The 4th byte: " .. buffer(3,1):uint())
end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 7777
udp_table:add(51001, cb_proto)