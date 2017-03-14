info("")
info("Loading Cerebus protocol v 2")

-- implementation of a simple stack
Stack = {}

-- Create a Table with stack functions
function Stack:Create(default_element)

  -- stack table
  local t = {}
  -- entry table
  t._et = {}
  t._default_element = default_element

  -- push a value on to the stack
  function t:push(...)
    if ... then
      local targs = {...}
      -- add values
      for _,v in ipairs(targs) do
        table.insert(self._et, v)
      end
    end
  end

  -- pop a value from the stack
  function t:pop(num)

    -- get num values from stack
    local num = num or 1

    -- return table
    local entries = {}

    -- get values into entries
    for i = 1, num do
      -- get last entry
      if #self._et ~= 0 then
        table.insert(entries, self._et[#self._et])
        -- remove last value
        table.remove(self._et)
      else
        break
      end
    end
    -- if we get fewer entries than requested, also include default (if not nil)
    if #entries < num and self._default_element ~= nil then
        table.insert(entries, self._default_element)
    end

    -- return unpacked entries
    return unpack(entries)
  end

  -- get entries
  function t:getn()
    return #self._et
  end

  -- list values
  function t:list()
    for i,v in pairs(self._et) do
      print(i, v)
    end
  end

  -- get last entry without removing
  function t:last()
      return #self._et > 0 and self._et[#self._et] or self._default_element
  end

  return t
end


local cbConst = {}
cbConst.cbMAXHOOPS = 4
cbConst.cbMAXSITES = 4
cbConst.cbMAXSITEPLOTS = ((cbConst.cbMAXSITES - 1) * cbConst.cbMAXSITES / 2)
cbConst.cbNUM_FE_CHANS        = 128                                       -- #Front end channels
cbConst.cbNUM_ANAIN_CHANS     = 16                                        -- #Analog Input channels
cbConst.cbNUM_ANALOG_CHANS    = (cbConst.cbNUM_FE_CHANS + cbConst.cbNUM_ANAIN_CHANS)      -- Total Analog Inputs
cbConst.cbNUM_ANAOUT_CHANS    = 4                                         -- #Analog Output channels
cbConst.cbNUM_AUDOUT_CHANS    = 2                                         -- #Audio Output channels
cbConst.cbNUM_ANALOGOUT_CHANS = (cbConst.cbNUM_ANAOUT_CHANS + cbConst.cbNUM_AUDOUT_CHANS) -- Total Analog Output
cbConst.cbNUM_DIGIN_CHANS     = 1                                         -- #Digital Input channels
cbConst.cbNUM_SERIAL_CHANS    = 1                                         -- #Serial Input channels
cbConst.cbNUM_DIGOUT_CHANS    = 4                                         -- #Digital Output channels
-- Total of all channels = 156
cbConst.cbMAXCHANS            = (cbConst.cbNUM_ANALOG_CHANS +
    cbConst.cbNUM_ANALOGOUT_CHANS + cbConst.cbNUM_DIGIN_CHANS +
    cbConst.cbNUM_SERIAL_CHANS + cbConst.cbNUM_DIGOUT_CHANS)
cbConst.cbLEN_STR_UNIT        = 8
cbConst.cbLEN_STR_LABEL       = 16
cbConst.cbLEN_STR_FILT_LABEL  = 16
cbConst.cbLEN_STR_IDENT       = 64
cbConst.cbMAXUNITS            = 5
cbConst.cbMAXNTRODES          = (cbConst.cbNUM_ANALOG_CHANS / 2)

klass = {}
function klass:new (o)
  o = o or {}
  setmetatable(o, self)
  self.__index = self
  return o
end

AField = klass:new{
    n='name',
    d=nil,
    ftype='afield',
}


PktField = AField:new{
    ftype='pktfield',
    t='UINT8',
    lf=nil,
    lfactor=1,
    len=nil,
    format='NONE',
    valuestring=nil,
    mask=nil,
    _data_width={
        UINT8=1,
        INT8=1,
        BYTES=1,
        UINT16=2,
        INT16=2,
        UINT32=4,
        INT32=4,
        FLOAT=4,
        STRING=1,
    },
    _data_rng_getter={
        UINT8='le_uint',
        INT8='le_int',
        UINT16='le_uint',
        INT16='le_int',
        UINT32='le_uint',
        INT32='le_int',
        FLOAT='le_float',
    }
}
function PktField:dataWidth()
    local dw = self._data_width[self.t]
    return dw
end
function PktField:rangeGetter()
    return self._data_rng_getter[self.t]
end

CbPkt = klass:new{
    name='HEADER',
    fields={
        PktField:new{t='UINT32', n='time', d='Timestamp in tics'},
        PktField:new{t='UINT16', n='chid', format='HEX_DEC'},
        PktField:new{t='UINT8', n='type', format='HEX'},
        PktField:new{t='UINT8', n='dlen', d='Packet Data Length (in quadlets)'}
    },
    dfields={},
    pkttypes={},
    _conf_pkg_ch=0x8000
}
function CbPkt:new(name, addfields)
    local newobj = klass:new()
    newobj.fields = {}
    for i, f in ipairs(self.fields) do
        newobj.fields[i] = f:new()
    end
    newobj.name = name
    newobj.dfields = {}
    addfields = addfields or {}
    for _, f in pairs(addfields) do
        table.insert(newobj.fields, f)
    end
    for i, f in ipairs(newobj.fields) do
        newobj.fields[f.n] = f
    end

    self.pkttypes[name] = newobj
    setmetatable(newobj, self)
    self.__index = self

    return newobj
end
function CbPkt:match(chid, type)
    for _,p in pairs(self.pkttypes) do
        if p.name ~= 'cbPKT_GENERIC' and p:match(chid, type) then
            return p
        end
    end
    return self.pkttypes['cbPKT_GENERIC']
end

function CbPkt:iterate(b_len)
    local i=0
    local n=#self.fields
    local buf_pos=0
    -- store how many bytes we expect in total. That's composed of 8 header bytes and the reported 'dlen'
    local dlen
    -- for k,v in pairs(self.dfields) do
    --     info("iterate key: " .. k .. " " .. v())
    -- end
    return function()
        i = i + 1
        if i <= n then
            local f = self.fields[i]
            if f.ftype=='afield' then
                return i, buf_pos, 0, f, 1
            end

            -- if dlen hasn't been read yet, test if it is available, read it from field; add header size
            if dlen == nil and self.dfields['dlen'] ~= nil and self.dfields['dlen']() ~= nil then
                dlen =  8 + self.dfields['dlen']()() * 4
            end

            local width = f:dataWidth()
            local field_w = width
            local mult = 1
            if f.len ~= nil then
                mult = f.len
            elseif f.lf ~= nil and self.dfields[f.lf] ~= nil then
                mult = f.lfactor * self.dfields[f.lf]()()
            end
            width = width * mult
            local old_buf_pos = buf_pos
            buf_pos = buf_pos + width
            if f.t=='BYTES' or f.t=='STRING' then
                field_w = width
                mult = 1
            end
            -- if we'd exceed buffer length (as passed through b_len) or dlen, stop by returning nil
            if (b_len ~= nil and buf_pos > b_len) or (dlen ~= nil and buf_pos > dlen) then return nil end
            return i, old_buf_pos, field_w, f, mult
        end
    end
end

-- Subclass for config packets. They all share that
-- chid == 0x8000 and 'type' corresponds to
CbPktConfig = CbPkt:new('')
function CbPktConfig:match(chid, type)
    return chid == self._conf_pkg_ch and
        self.fields['type'].valuestring ~= nil and
        self.fields['type'].valuestring[type] ~= nil
end


-- Generic packets

CbPktGeneric = CbPkt:new('cbPKT_GENERIC',
    {
        PktField:new{t='BYTES', n='data', lf='dlen', lfactor=4},
    }
)
function CbPktGeneric:match(chid, type)
    return true
end

-- System heartbeat
CbPktSysHeartbeat = CbPkt:new('cbPKT_SYSHEARTBEAT')
function CbPktSysHeartbeat:match(chid, type)
    return chid == self._conf_pkg_ch and type == 0x00
end

-- System protocol monitor
CbPktSysProtocolMonitor = CbPkt:new('cbPKT_SYSPROTOCOLMONITOR',
    {
        PktField:new{t='UINT32', n='sentpkts', d='Packets sent since last cbPKT_SYSPROTOCOLMONITOR (or 0 if timestamp=0)'},
    }
)
function CbPktSysProtocolMonitor:match(chid, type)
    return chid == self._conf_pkg_ch and type == 0x01
end

-- System condition report packet
CbPktSysInfo = CbPkt:new('cbPKT_SYSINFO',
    {
        PktField:new{t='UINT32', n='sysfreq', d='System clock frequency in Hz', format='DEC'},
        PktField:new{t='UINT32', n='spikelen', d='The length of the spike events', format='DEC'},
        PktField:new{t='UINT32', n='spikepre', d='Spike pre-trigger samples', format='DEC'},
        PktField:new{t='UINT32', n='resetque', d='The channel for the reset to que on', format='DEC'},
        PktField:new{t='UINT32', n='runlevel', d='System runlevel', format='DEC_HEX'},
        PktField:new{t='UINT32', n='runflags', d='System clock frequency in Hz', format='HEX'},
    }
)
CbPktSysInfo.fields['type'].valuestring = {
    [0x10] = "System Condition Report cbPKTTYPE_SYSREP",
    [0x11] = "System Spike Length Report cbPKTTYPE_SYSREPSPKLEN",
    [0x12] = "System Runlevel Report cbPKTTYPE_SYSREPRUNLEV",
    [0x90] = "System set Req cbPKTTYPE_SYSSET",
    [0x91] = "System set Spike Length cbPKTTYPE_SYSSETSPKLEN",
    [0x92] = "System set Runlevel cbPKTTYPE_SYSSETRUNLEV",
}
function CbPktSysInfo:match(chid, type)
    local p_types = {
        [0x10] = true,
        [0x11] = true,
        [0x12] = true,
        [0x90] = true,
        [0x91] = true,
        [0x92] = true,
    }
    return chid == self._conf_pkg_ch and  p_types[type] ~= nil
end


-- System condition report packet
CbPktSSModelSet = CbPktConfig:new('cbPKT_SS_MODELSET',
    {
        PktField:new{t='UINT32', n='chan', d='Channel being configured (zero-based)', format='DEC'},
        PktField:new{t='UINT32', n='unit_number', d='unit number (0 = noise)', format='DEC'},
        PktField:new{t='UINT32', n='valid', valuestring={[0]="invalid", [1]="valid"}, format='DEC'},
        PktField:new{t='UINT32', n='inverted', valuestring={[0]="not inverted", [1]="inverted"}, format='DEC'},
        PktField:new{t='INT32', n='num_samples', d='non-zero value means that the block stats are valid', format='DEC'},
        PktField:new{t='FLOAT', n='mu', len=2},
        PktField:new{t='FLOAT', n='Sigma_x', len=4},
        PktField:new{t='FLOAT', n='determinant_Sigma_x'},
        PktField:new{t='FLOAT', n='Sigma_x_inv', len=4},
        PktField:new{t='FLOAT', n='log_determinant_Sigma_x'},
        PktField:new{t='FLOAT', n='subcluster_spread_factor_numerator'},
        PktField:new{t='FLOAT', n='subcluster_spread_factor_denominator'},
        PktField:new{t='FLOAT', n='mu_e'},
        PktField:new{t='FLOAT', n='sigma_e_squared'},

    }
)
CbPktSSModelSet.fields['type'].valuestring = {
    [0x51] = "SS Model response cbPKTTYPE_SS_MODELREP",
    [0xD1] = "SS Model request cbPKTTYPE_SS_MODELSET",
}

-- NTrode Information Packets
CbPktNTrodeInfo = CbPktConfig:new('cbPKT_NTRODEINFO',
    {
        PktField:new{t='UINT32', n='ntrode', d='nTrode being configured (1-based)', format='DEC'},
        PktField:new{t='STRING', n='label', d='nTrode label', len=cbConst.cbLEN_STR_LABEL},
        AField:new{n='placeholder', d='→ Other fields of this packet have not been implemented yet. ←'}
        -- typedef struct {
        --     INT16       nOverride;
        --     INT16       afOrigin[3];
        --     INT16       afShape[3][3];
        --     INT16       aPhi;
        --     UINT32      bValid; // is this unit in use at this time?
        --                         // BOOL implemented as UINT32 - for structure alignment at paragraph boundary
        -- } cbMANUALUNITMAPPING;
        -- cbMANUALUNITMAPPING ellipses[cbMAXSITEPLOTS][cbMAXUNITS];  // unit mapping
        -- UINT16 nSite;          // number channels in this NTrode ( 0 <= nSite <= cbMAXSITES)
        -- UINT16 fs;             // NTrode feature space cbNTRODEINFO_FS_*
        -- UINT16 nChan[cbMAXSITES];  // group of channels in this NTrode
    }
)
CbPktNTrodeInfo.fields['type'].valuestring = {
    [0x27] = "NTrode info response cbPKTTYPE_REPNTRODEINFO",
    [0xA7] = "NTrode info request cbPKTTYPE_SETNTRODEINFO",
}

-- Channel Information Packets
CbPktChanInfo = CbPktConfig:new('cbPKT_CHANINFO',
    {
        PktField:new{t='UINT32', n='chan', d='channel being configured', format='DEC'},
        PktField:new{t='UINT32', n='proc', d='address of the processor', format='DEC'},
        PktField:new{t='UINT32', n='bank', d='address of the bank', format='DEC'},
        PktField:new{t='UINT32', n='term', d='terminal number', format='DEC_HEX'},
        PktField:new{t='UINT32', n='chancaps', d='channel capabilities', format='HEX'},
        PktField:new{t='UINT32', n='doutcaps', d='digital output capablities', format='HEX'},
        PktField:new{t='UINT32', n='dinpcaps', d='digital input capablities', format='HEX'},
        PktField:new{t='UINT32', n='aoutcaps', d='analog output capablities', format='HEX'},
        PktField:new{t='UINT32', n='ainpcaps', d='analog input capablities', format='HEX'},
        PktField:new{t='UINT32', n='spkcaps', d='spike capablities', format='HEX'},

        AField:new{n='physcalin', d='physical channel scaling information'},
        PktField:new{t='INT16', n='physcalin.digmin', d='digital value that cooresponds with the anamin value'},
        PktField:new{t='INT16', n='physcalin.digmax', d='digital value that cooresponds with the anamax value'},
        PktField:new{t='INT32', n='physcalin.anamin', d='minimum analog value present in the signal'},
        PktField:new{t='INT32', n='physcalin.anamax', d='maximum analog value present in the signal'},
        PktField:new{t='INT32', n='physcalin.anagain', d='gain applied to the default analog values to get the analog values'},
        PktField:new{t='STRING', n='physcalin.anaunit', d='nTrode label', len=cbConst.cbLEN_STR_UNIT},

        AField:new{n='phyfiltin', d='physical channel filter definition'},
        PktField:new{t='STRING', n='phyfiltin.label', d='filter label', len=cbConst.cbLEN_STR_FILT_LABEL},
        PktField:new{t='UINT32', n='phyfiltin.hpfreq', d='high-pass corner frequency in milliHertz'},
        PktField:new{t='UINT32', n='phyfiltin.hporder', d='high-pass filter order'},
        PktField:new{t='UINT32', n='phyfiltin.hptype', d='high-pass filter type', format='HEX'},
        PktField:new{t='UINT32', n='phyfiltin.lpfreq', d='low-pass frequency in milliHertz'},
        PktField:new{t='UINT32', n='phyfiltin.lporder', d='low-pass filter order'},
        PktField:new{t='UINT32', n='phyfiltin.lptype', d='low-pass filter type', format='HEX'},

        -- PktField:new{t='STRING', n='label', d='nTrode label', len=cbConst.cbLEN_STR_LABEL},
        AField:new{n='placeholder', d='→ Other fields of this packet have not been implemented yet. ←'},
        -- typedef struct {
        --     INT16   digmin;     // digital value that cooresponds with the anamin value
        --     INT16   digmax;     // digital value that cooresponds with the anamax value
        --     INT32   anamin;     // the minimum analog value present in the signal
        --     INT32   anamax;     // the maximum analog value present in the signal
        --     INT32   anagain;    // the gain applied to the default analog values to get the analog values
        --     char    anaunit[cbLEN_STR_UNIT]; // the unit for the analog signal (eg, "uV" or "MPa")
        -- } cbSCALING;

        -- typedef struct {
        --     char    label[cbLEN_STR_FILT_LABEL];
        --     UINT32  hpfreq;     // high-pass corner frequency in milliHertz
        --     UINT32  hporder;    // high-pass filter order
        --     UINT32  hptype;     // high-pass filter type
        --     UINT32  lpfreq;     // low-pass frequency in milliHertz
        --     UINT32  lporder;    // low-pass filter order
        --     UINT32  lptype;     // low-pass filter type
        -- } cbFILTDESC;

    }
)
CbPktChanInfo.fields['type'].valuestring = {
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
}


-- Preview Stream
CbPktStreamPrev = CbPkt:new('cbPKT_STREAMPREV',
    {
        PktField:new{t='INT16', n='rawmin', format='DEC'},
        PktField:new{t='INT16', n='rawmax'},
        PktField:new{t='INT16', n='smpmin'},
        PktField:new{t='INT16', n='smpmax'},
        PktField:new{t='INT16', n='spkmin'},
        PktField:new{t='INT16', n='spkmax'},
        PktField:new{t='UINT32', n='spkmos'},
        PktField:new{t='UINT32', n='eventflag'},
        PktField:new{t='INT16', n='envmin'},
        PktField:new{t='INT16', n='envmax'},
        PktField:new{t='INT32', n='spkthrlevel'},
        PktField:new{t='UINT32', n='nWaveNum'},
        PktField:new{t='UINT32', n='nSampleRows'},
        PktField:new{t='UINT32', n='nFlags'},
    }
)
function CbPktStreamPrev:match(chid, type)
    local p_types = {
        -- [0x81] = true,
        -- [0x82] = true,
        -- [0x83] = true,
        -- [0x03] = true,
        -- [0x01] = true,
        [0x02] = true,
    }
    return bit32.band(chid, 0x8FFF) > self._conf_pkg_ch and p_types[type] ~= nil
end

ProtoMaker = klass:new{
    name='Cerebus',
    desc="Cerebus NSP Communication",
    colname="Cerebus",
    port=51001
}
function ProtoMaker:new(o)
    -- info("ProtoMaker:new")
    o = o or {}
    local newobj = klass.new(self)
    for k,v in pairs(o) do newobj[k] = v end
    newobj.proto = Proto(newobj.name, newobj.desc)
    newobj.pfields = newobj.proto.fields
    newobj.fByPkt = {}
    -- info("ProtoMaker:new proto ..." .. newobj.name ..", " .. newobj.desc)
    return newobj
end
function ProtoMaker:register()
    info("register proto ...")

    for _,p in pairs(CbPkt.pkttypes) do
        self:makeFieldsForPacket(p)
    end


    function self.proto.dissector(buffer, pinfo, tree)
        -- info("self.proto.dissector ...")

        pinfo.cols.protocol = self.colname
        local buflen = buffer:len()
        local offset = 0
        local header_len = 8
        local buf_remain = buffer():tvb()
        local i = 0
        while buflen >= header_len do
            local chid = buf_remain(4,2):le_uint()
            local ptype = buf_remain(6,1):uint()
            local packet = CbPkt:match(chid, ptype)
            -- get current
            local packet_len = buf_remain(7,1):uint() * 4 + header_len
            -- info(packet.name)
            if i == 0 then
                pinfo.cols.info = packet.name
            end

            local subtree = tree:add(self.proto, buf_remain(0, packet_len), "Cerebus Protocol Data (" .. packet.name .. ")" )

            self:addSubtreeForPkt(buf_remain(0, packet_len):tvb(), subtree, packet)
            buflen = buflen - packet_len
            buf_remain = buf_remain(packet_len):tvb()
            i = i + 1
        end
        if i > 1 then
            pinfo.cols.info:append(" (+ " .. (i-1) .. " other" .. (i>2 and 's' or '') .. ")")
        end
    end
    local udp_table = DissectorTable.get("udp.port")
    -- register our protocol to handle udp port (default 51001)
    udp_table:add(self.port, self.proto)
end
function ProtoMaker:makeFieldsForPacket(pkt)
    local n = self.name .. "." .. pkt.name .. "."
    local fn = pkt.name .. "_"
    self.fByPkt[pkt] = {}
    for i, f in ipairs(pkt.fields) do
        if f.ftype~='afield' then
            local thisfn = fn .. f.n
            local thisn = n .. f.n
            local pf = ProtoField.new(f.d and f.d or f.n, thisn, ftypes[f.t], f.valuestring, base[f.format], f.mask, f.d)
            self.pfields[thisfn] = pf
            self.fByPkt[pkt][f.n] = pf
            local df = Field.new(thisn)
            table.insert(pkt.dfields, df)
            pkt.dfields[f.n] = df
        end
    end
     -- .. " " .. pkt.dfields[f.n] .. " " .. self.fByPkt[pkt])
end

function ProtoMaker:addSubtreeForPkt(buffer, tree, pkt)
    local tree_stack = Stack:Create({t=tree, p=""})

    for i, bPos, width, pf, mult in pkt:iterate(buffer:len()) do
        local current_parent = nil
        repeat
            local last_tree = tree_stack:last()
            local i,j = string.find(pf.n, last_tree.p)
            if i==1 and j > 0 and string.sub(pf.n, j+1, j+1)=='.' then
                current_parent = last_tree.t
                -- tree_stack:push(last_tree)
            elseif i==1 and j==0 then
                current_parent = last_tree.t
            else
                tree_stack:pop()
            end
        until current_parent ~= nil
        local subtree
        if pf.ftype == 'afield' then
            subtree = current_parent:add(pf.d ~= nil and pf.d or pf.n )
        else
            subtree = current_parent:add_le(self.fByPkt[pkt][pf.n], buffer(bPos, width))
            if mult > 1 then
                local n = mult - 1
                subtree:append_text(" and "..n.." more item"..(n>1 and "s" or ""))
                for i=1,n do
                    local brng = buffer(bPos + width * i, width)
                    subtree:add( brng, 'item '..i..': ' .. brng[pf:rangeGetter()](brng))
                end
            end
        end
        tree_stack:push({t=subtree, p=pf.n})

    end
end


local pm = ProtoMaker:new()
pm:register()
