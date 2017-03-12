-- do not modify this table
local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}
-- set this DEBUG to debug_level.LEVEL_1 to enable printing debug_level info
-- set it to debug_level.LEVEL_2 to enable really verbose printing
-- note: this will be overridden by user's preference settings
local DEBUG = debug_level.LEVEL_1
local default_settings =
{
    debug_level  = DEBUG,
    port         = 51001,
}


local dprint = function() end
local dprint2 = function() end
local function reset_debug_level()
    if default_settings.debug_level > debug_level.DISABLED then
        dprint = function(...)
            print(table.concat({"Lua:", ...}," "))
        end

        if default_settings.debug_level > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    end
end
-- call it now
reset_debug_level()


-- cb protocol
local CB_HDR_LEN = 8

-- Human readble package type descriptions
local pconftypes = {
        [0x00] = "System Heartbeat cbPKTTYPE_SYSHEARTBEAT",
        [0x01] = "Protocol monitoring packet cbPKTTYPE_SYSPROTOCOLMONITOR",
        [0x5c] = "nPlay configuration response cbPKTTYPE_NPLAYREP",
        [0xdc] = "nPlay configuration request cbPKTTYPE_NPLAYSET",
        [0x5e] = "nPlay trigger response cbPKTTYPE_TRIGGERREP",
        [0xde] = "nPlay trigger request cbPKTTYPE_TRIGGERSET",
        [0x5f] = "video tracking event cbPKTTYPE_VIDEOTRACKREP",
        [0xdf] = "video tracking request cbPKTTYPE_VIDEOTRACKSET",
        [0x63] = "log event response cbPKTTYPE_LOGREP",
        [0xe3] = "log event request cbPKTTYPE_LOGSET",
        [0x88] = "config request cbPKTTYPE_REQCONFIGALL",
        [0x08] = "config response cbPKTTYPE_REPCONFIGALL",
        [0x10] = "System Condition Report cbPKTTYPE_SYSREP",
        [0x11] = "System Spike Length Report cbPKTTYPE_SYSREPSPKLEN",
        [0x12] = "System Runlevel Report cbPKTTYPE_SYSREPRUNLEV",
        [0x90] = "System set Req cbPKTTYPE_SYSSET",
        [0x91] = "System set Spike Length cbPKTTYPE_SYSSETSPKLEN",
        [0x92] = "System set Runlevel cbPKTTYPE_SYSSETRUNLEV",
}

-- declare our protocol
local cb_proto = Proto("Cerebus","Cerebus NSP Communication")
local f = cb_proto.fields
f.f_tstamp = ProtoField.uint32("Cerebus.TStamp", "Timestamp", base.HEX_DEC)
f.f_chid = ProtoField.uint16("Cerebus.ChannelId","Channel Id",base.HEX_DEC)
f.f_pkttype = ProtoField.uint8("Cerebus.PktType","Packet Type",base.HEX_DEC, pconftypes)

f.f_dlen= ProtoField.uint8("Cerebus.DLen","Data length",base.HEX_DEC)
f.f_data = ProtoField.bytes("Cerebus.Data","Data")

-- special fields for system packets 0x10, 11, 12, 90, 91, 92
f.sys_sysfreq = ProtoField.uint32("Cerebus.SysInfo.Sysfreq", "System frequency", base.DEC)
f.sys_spikelen = ProtoField.uint32("Cerebus.SysInfo.Spikelen", "length of spike events", base.DEC)
f.sys_spikepre = ProtoField.uint32("Cerebus.SysInfo.Spikepre", "number of pre-trigger samples", base.DEC)

-- some error expert info's
local ef_too_short = ProtoExpert.new("Cerebus.too_short.expert", "Cerebus message too short", expert.group.MALFORMED, expert.severity.ERROR)
cb_proto.experts = {ef_too_short}

-- create a function to dissect it
function cb_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "Cerebus"-- cb_proto.name
    local pktlen = buffer:reported_length_remaining()
    local subtree = tree:add(cb_proto, buffer(0, pktlen), "Cerebus Protocol Data")

    -- now let's check it's not too short
    if pktlen < CB_HDR_LEN then
        -- since we're going to add this protocol to a specific UDP port, we're going to
        -- assume packets in this port are our protocol, so the packet being too short is an error
        subtree:add_proto_expert_info(ef_too_short)
        dprint("packet length", pktlen, "too short")
        return
    end
    if pinfo.src_port == default_settings.port then
        pinfo.cols.info:set("Response")
    else
        pinfo.cols.info:set("Query")
    end

	subtree:add_le(f.f_tstamp, buffer(0,4))

	--    subtree:add_le(buffer(0,4),"Timestamp: " .. buffer(0,4):le_uint())
	subtree:add_le(f.f_chid, buffer(4,2))
    local cfg_pkt = false
    local pkttype
	if bit32.band(buffer(4,2):le_uint(), 0x8000) ~= 0 then
        cfg_pkt = true
        subtree:add_le(f.f_pkttype, buffer(6,1))
        pkttype = buffer(6,1):uint()
        pinfo.cols.info:append(" (".. string.format("0x%02x", pkttype) ..")")
    end

    local dlen = buffer(7,1):uint()
    subtree:add_le(f.f_dlen, buffer(7,1))

    if pkttype == 0x10 or pkttype == 0x11 or pkttype == 0x12 or pkttype == 0x90 or pkttype == 0x91 or pkttype == 0x92 then
        subtree:add_le(f.sys_sysfreq, buffer(8, 4))
        subtree:add_le(f.sys_spikelen, buffer(12, 4))
        return
    end



    if dlen > 0 then
        subtree:add(f.f_data, buffer(8, dlen * 4))
    end
--	subtree:add(buffer(6,1),"Packet type: " .. buffer(6,1):uint())
    -- subtree = subtree:add(buffer(2,2),"The next two bytes")
    -- subtree:add(buffer(2,1),"The 3rd byte: " .. buffer(2,1):uint())
    -- subtree:add(buffer(3,1),"The 4th byte: " .. buffer(3,1):uint())
end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 7777
udp_table:add(51001, cb_proto)
