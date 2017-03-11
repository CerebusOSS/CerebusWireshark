-- cb protocol
-- declare our protocol
local cb_proto = Proto("Cerebus","Cerebus NSP Communication")
local f = cb_proto.fields
f.f_tstamp = ProtoField.uint32("Cerebus.TStamp", "Timestamp", base.HEX_DEC)
f.f_chid = ProtoField.uint16("Cerebus.ChannelId","Channel Id",base.HEX_DEC)
f.f_pkttype = ProtoField.uint8("Cerebus.PktType","Packet Type",base.HEX_DEC)
f.f_dlen= ProtoField.uint8("Cerebus.DLen","Data length",base.HEX_DEC)
f.f_data = ProtoField.bytes("Cerebus.Data","Data")
--f.fields = {cb_proto.f_tstamp, cb_proto.f_chid, cb_proto.f_pkttype, f.f_dlen, cb_proto.f_data}
-- create a function to dissect it
function cb_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = cb_proto.name
    local subtree = tree:add(cb_proto, buffer(), "Cerebus Protocol Data")
	subtree:add_le(f.f_tstamp, buffer(0,4))

	--    subtree:add_le(buffer(0,4),"Timestamp: " .. buffer(0,4):le_uint())
	subtree:add_le(f.f_chid, buffer(4,2))
	subtree:add_le(f.f_pkttype, buffer(6,1))
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