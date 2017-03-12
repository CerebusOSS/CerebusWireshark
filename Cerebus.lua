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
        [0x29] = "Video/external synch response cbPKTTYPE_VIDEOSYNCHREP",
        [0xa9] = "Video/external synch request cbPKTTYPE_VIDEOSYNCHSET",
        [0x31] = "Comment annotation response cbPKTTYPE_COMMENTREP",
        [0xb1] = "Comment annotation request cbPKTTYPE_COMMENTSET",
        [0x32] = "NeuroMotive response cbPKTTYPE_NMREP",
        [0xb2] = "NeuroMotive request cbPKTTYPE_NMSET",
        [0x21] = "Report Processor Information cbPKTTYPE_PROCREP",
        [0x22] = "Report Bank Information cbPKTTYPE_BANKREP",
        [0x23] = "Report Filter Information cbPKTTYPE_FILTREP",
        [0xa3] = "Set Filter Information cbPKTTYPE_FILTSET",
        [0x24] = "Factory default response cbPKTTYPE_CHANRESETREP",
        [0xa4] = "Factory default request cbPKTTYPE_CHANRESET",
        [0x25] = "Adaptive filtering response cbPKTTYPE_ADAPTFILTREP",
        [0xa5] = "Adaptive filtering request cbPKTTYPE_ADAPTFILTSET",
        [0x26] = "Reference Electrode filtering response cbPKTTYPE_REFELECFILTREP",
        [0xa6] = "Reference Electrode filtering request cbPKTTYPE_REFELECFILTSET",
        [0x27] = "NTrode Information response cbPKTTYPE_REPNTRODEINFO",
        [0xa7] = "NTrode Information request cbPKTTYPE_SETNTRODEINFO",
        [0x30] = "Sample Group response cbPKTTYPE_GROUPREP",
        [0xb0] = "Sample Group request cbPKTTYPE_GROUPSET",
        [0x40] = "cbPKTTYPE_CHANREP",
        [0x41] = "cbPKTTYPE_CHANREPLABEL",
        [0x42] = "cbPKTTYPE_CHANREPSCALE",
        [0x43] = "cbPKTTYPE_CHANREPDOUT",
        [0x44] = "cbPKTTYPE_CHANREPDINP",
        [0x45] = "cbPKTTYPE_CHANREPAOUT",
        [0x46] = "cbPKTTYPE_CHANREPDISP",
        [0x47] = "cbPKTTYPE_CHANREPAINP",
        [0x48] = "cbPKTTYPE_CHANREPSMP",
        [0x49] = "cbPKTTYPE_CHANREPSPK",
        [0x4A] = "cbPKTTYPE_CHANREPSPKTHR",
        [0x4B] = "cbPKTTYPE_CHANREPSPKHPS",
        [0x4C] = "cbPKTTYPE_CHANREPUNITOVERRIDES",
        [0x4D] = "cbPKTTYPE_CHANREPNTRODEGROUP",
        [0x4E] = "cbPKTTYPE_CHANREPREJECTAMPLITUDE",
        [0x4F] = "cbPKTTYPE_CHANREPAUTOTHRESHOLD",
        [0xC0] = "cbPKTTYPE_CHANSET",
        [0xC1] = "cbPKTTYPE_CHANSETLABEL",
        [0xC2] = "cbPKTTYPE_CHANSETSCALE",
        [0xC3] = "cbPKTTYPE_CHANSETDOUT",
        [0xC4] = "cbPKTTYPE_CHANSETDINP",
        [0xC5] = "cbPKTTYPE_CHANSETAOUT",
        [0xC6] = "cbPKTTYPE_CHANSETDISP",
        [0xC7] = "cbPKTTYPE_CHANSETAINP",
        [0xC8] = "cbPKTTYPE_CHANSETSMP",
        [0xC9] = "cbPKTTYPE_CHANSETSPK",
        [0xCA] = "cbPKTTYPE_CHANSETSPKTHR",
        [0xCB] = "cbPKTTYPE_CHANSETSPKHPS",
        [0xCC] = "cbPKTTYPE_CHANSETUNITOVERRIDES",
        [0xCD] = "cbPKTTYPE_CHANSETNTRODEGROUP",
        [0xCE] = "cbPKTTYPE_CHANSETREJECTAMPLITUDE",
        [0xCF] = "cbPKTTYPE_CHANSETAUTOTHRESHOLD",
        [0xE0] = "cbPKTTYPE_MASKED_REFLECTED",
        [0xF0] = "cbPKTTYPE_COMPARE_MASK_REFLECTED",
        [0x7F] = "cbPKTTYPE_REFLECTED_CONVERSION_MASK",
        [0x61] = "cbPKTTYPE_REPFILECFG",
        [0xE1] = "cbPKTTYPE_SETFILECFG",
        [0x64] = "cbPKTTYPE_REPPATIENTINFO",
        [0xE4] = "cbPKTTYPE_SETPATIENTINFO",
        [0x65] = "cbPKTTYPE_REPIMPEDANCE",
        [0xE5] = "cbPKTTYPE_SETIMPEDANCE",
        [0x67] = "cbPKTTYPE_REPPOLL",
        [0xE7] = "cbPKTTYPE_SETPOLL",
        [0x66] = "cbPKTTYPE_REPINITIMPEDANCE",
        [0xE6] = "cbPKTTYPE_SETINITIMPEDANCE",
        [0x68] = "cbPKTTYPE_REPMAPFILE",
        [0xE8] = "cbPKTTYPE_SETMAPFILE",
        [0x50] = "cbPKTTYPE_SS_MODELALLREP",
        [0xD0] = "cbPKTTYPE_SS_MODELALLSET",
        [0x51] = "cbPKTTYPE_SS_MODELREP",
        [0xD1] = "cbPKTTYPE_SS_MODELSET",
        [0x52] = "cbPKTTYPE_SS_DETECTREP",
        [0xD2] = "cbPKTTYPE_SS_DETECTSET",
        [0x53] = "cbPKTTYPE_SS_ARTIF_REJECTREP",
        [0xD3] = "cbPKTTYPE_SS_ARTIF_REJECTSET",
        [0x54] = "cbPKTTYPE_SS_NOISE_BOUNDARYREP",
        [0xD4] = "cbPKTTYPE_SS_NOISE_BOUNDARYSET",
        [0x55] = "cbPKTTYPE_SS_STATISTICSREP",
        [0xD5] = "cbPKTTYPE_SS_STATISTICSSET",
        [0x56] = "cbPKTTYPE_SS_RESETREP",
        [0xD6] = "cbPKTTYPE_SS_RESETSET",
        [0x57] = "cbPKTTYPE_SS_STATUSREP",
        [0xD7] = "cbPKTTYPE_SS_STATUSSET",
        [0x58] = "cbPKTTYPE_SS_RESET_MODEL_REP",
        [0xD8] = "cbPKTTYPE_SS_RESET_MODEL_SET",
        [0x59] = "cbPKTTYPE_SS_RECALCREP",
        [0xD9] = "cbPKTTYPE_SS_RECALCSET",
        [0x5B] = "cbPKTTYPE_FS_BASISREP",
        [0xDB] = "cbPKTTYPE_FS_BASISSET",
        [0x28] = "cbPKTTYPE_LNCREP",
        [0xA8] = "cbPKTTYPE_LNCSET",
        [0x5D] = "cbPKTTYPE_SET_DOUTREP",
        [0xDD] = "cbPKTTYPE_SET_DOUTSET",
        [0x33] = "cbPKTTYPE_WAVEFORMREP",
        [0xB3] = "cbPKTTYPE_WAVEFORMSET",

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
f.sys_resetque = ProtoField.uint32("Cerebus.SysInfo.Resetque", "channel for the reset to que on", base.DEC)
local sys_runlevels = {
    [10] = "cbRUNLEVEL_STARTUP",
    [20] = "cbRUNLEVEL_HARDRESET",
    [30] = "cbRUNLEVEL_STANDBY",
    [40] = "cbRUNLEVEL_RESET",
    [50] = "cbRUNLEVEL_RUNNING",
    [60] = "cbRUNLEVEL_STRESSED",
    [70] = "cbRUNLEVEL_ERROR",
    [80] = "cbRUNLEVEL_SHUTDOWN",
}
f.sys_runlevel = ProtoField.uint32("Cerebus.SysInfo.Runlevel", "system runlevel", base.DEC, sys_runlevels)
f.sys_runflags = ProtoField.uint32("Cerebus.SysInfo.Runflags", "run flags", base.HEX)

-- special fields for comment packets 0x31, 0xb1
local comment_info_charsets = {
    [0] = "ANSI",
    [1] = "UTF16",
    [255] = "NeuroMotive ANSI",
}
f.comment_info_charset = ProtoField.uint8("Cerebus.Comment.Info.Charset", "Charset", base.DEC, comment_info_charsets)
local comment_info_flags = {
    [0] = "RGBA",
    [1] = "TIMESTAMP",
}
f.comment_info_flags = ProtoField.uint8("Cerebus.Comment.Info.Flags", "Flags", base.HEX, comment_info_flags)
f.comment_info_reserved = ProtoField.bytes("Cerebus.Comment.Info.Reserved", "Reserved")
f.comment_data = ProtoField.uint32("Cerebus.Comment.Data", "Data", base.HEX_DEC)
f.comment_comment = ProtoField.string("Cerebus.Comment.Comment", "Comment")

-- special fields for sample group packets 0x30, 0xb0
f.sgroup_proc = ProtoField.uint32("Cerebus.SGroup.Proc", "Proc", base.DEC)
f.sgroup_group = ProtoField.uint32("Cerebus.SGroup.Group", "Group", base.DEC)
f.sgroup_label = ProtoField.string("Cerebus.SGroup.Label", "Label")
f.sgroup_period = ProtoField.uint32("Cerebus.SGroup.Period", "Sampling Period", base.DEC)
f.sgroup_length = ProtoField.uint32("Cerebus.SGroup.Length", "Length", base.DEC)
f.sgroup_list = ProtoField.bytes("Cerebus.SGroup.List", "Channel list")
local sgroup_length_field = Field.new("Cerebus.SGroup.Length")

-- some error expert info's
local ef_too_short = ProtoExpert.new("Cerebus.too_short.expert", "Cerebus message too short", expert.group.MALFORMED, expert.severity.ERROR)
cb_proto.experts = {ef_too_short}


local channelId_field       = Field.new("Cerebus.ChannelId")
local pktType_field       = Field.new("Cerebus.PktType")

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
        pinfo.cols.info:set("R:")
    else
        pinfo.cols.info:set("Q:")
    end
	subtree:add_le(f.f_tstamp, buffer(0,4))

	--    subtree:add_le(buffer(0,4),"Timestamp: " .. buffer(0,4):le_uint())
	subtree:add_le(f.f_chid, buffer(4,2))
    local cfg_pkt = false
    local pkttype
	if bit32.band(buffer(4,2):le_uint(), 0x8000) ~= 0 then
        cfg_pkt = true
        subtree:add_le(f.f_pkttype, buffer(6,1))
        pkttype = pktType_field()()
        pinfo.cols.info:append(" (".. string.format("0x%02x", pkttype) ..")")
    end

    local dlen = buffer(7,1):uint()
    subtree:add_le(f.f_dlen, buffer(7,1))

    if pkttype == 0x10 or pkttype == 0x11 or pkttype == 0x12 or pkttype == 0x90 or pkttype == 0x91 or pkttype == 0x92 then
        subtree:add_le(f.sys_sysfreq, buffer(8, 4))
        subtree:add_le(f.sys_spikelen, buffer(12, 4))
        subtree:add_le(f.sys_spikepre, buffer(16, 4))
        subtree:add_le(f.sys_resetque, buffer(20, 4))
        subtree:add_le(f.sys_runlevel, buffer(24, 4))
        subtree:add_le(f.sys_runflags, buffer(28, 4))
        return
    elseif pkttype == 0x31 or pkttype == 0xb1 then
        subtree:add(f.comment_info_charset, buffer(8, 1))
        subtree:add(f.comment_info_flags, buffer(9, 1))
        subtree:add(f.comment_info_reserved, buffer(10, 2))
        subtree:add_le(f.comment_data, buffer(12, 4))
        subtree:add(f.comment_comment, buffer(16, 128))
        return
    elseif pkttype == 0x30 or pkttype == 0xb0 then
        subtree:add_le(f.sgroup_proc, buffer(8, 4))
        subtree:add_le(f.sgroup_group, buffer(12, 4))
        subtree:add(f.sgroup_label, buffer(16, 16))
        subtree:add_le(f.sgroup_period, buffer(32, 4))
        local listtree = subtree:add_le(f.sgroup_length, buffer(36, 4))
        listtree:prepend_text("Channel List (")
        listtree:append_text(")")
        local listlen = sgroup_length_field()()
        for li = 1,listlen do
            listtree:add(buffer(36+li*4, 4), buffer(36+li*4, 4):le_uint())
        end
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
