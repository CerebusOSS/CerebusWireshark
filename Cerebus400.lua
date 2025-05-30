-- Wireshark dissector for UDP packets exchanged between
-- Neural Signal Processors and controlling PCs
--
-- Copyright 2017 Jonas Zimmermann, 2022 Hyrum Sessions

-- info("Loading cb protocol ...")

-- Definition of a few helpers

-- implementation of a simple stack (Lifted from http://lua-users.org/wiki/SimpleStack)
-- and extended
local Stack = {}

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

-- define Constants, lifted from cbhwlib.h
local cbConst = {}
cbConst.cbMAXHOOPS = 4
cbConst.cbMAXSITES = 4
cbConst.cbMAXSITEPLOTS = ((cbConst.cbMAXSITES - 1) * cbConst.cbMAXSITES / 2)
cbConst.cbNUM_FE_CHANS        = 256                                       -- #Front end channels
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

cbConst.cbFIRST_FE_CHAN       = 0                                                          -- 0   First Front end channel
cbConst.cbFIRST_ANAIN_CHAN    = cbConst.cbNUM_FE_CHANS                                     -- 256 First Analog Input channel
cbConst.cbFIRST_ANAOUT_CHAN   = (cbConst.cbFIRST_ANAIN_CHAN + cbConst.cbNUM_ANAIN_CHANS)   -- 288 First Analog Output channel
cbConst.cbFIRST_AUDOUT_CHAN   = (cbConst.cbFIRST_ANAOUT_CHAN + cbConst.cbNUM_ANAOUT_CHANS) -- 296 First Audio Output channel
cbConst.cbFIRST_DIGIN_CHAN    = (cbConst.cbFIRST_AUDOUT_CHAN + cbConst.cbNUM_AUDOUT_CHANS) -- 300 First Digital Input channel
cbConst.cbFIRST_SERIAL_CHAN   = (cbConst.cbFIRST_DIGIN_CHAN + cbConst.cbNUM_DIGIN_CHANS)   -- 302 First Serial Input channel
cbConst.cbFIRST_DIGOUT_CHAN   = (cbConst.cbFIRST_SERIAL_CHAN + cbConst.cbNUM_SERIAL_CHANS) -- 304 First Digital Output channel


cbConst.cbLEN_STR_UNIT        = 8
cbConst.cbLEN_STR_LABEL       = 16
cbConst.cbLEN_STR_FILT_LABEL  = 16
cbConst.cbLEN_STR_IDENT       = 64
cbConst.cbMAXUNITS            = 5
cbConst.cbMAXNTRODES          = (cbConst.cbNUM_ANALOG_CHANS / 2)
cbConst.cbPKT_SPKCACHELINECNT = cbConst.cbNUM_ANALOG_CHANS

cbConst.cbMAX_PNTS            = 128


-- base of our rudimentary class system
local klass = {}
function klass:new (o)
  o = o or {}
  setmetatable(o, self)
  self.__index = self
  return o
end

local AField = klass:new{
    n='name',
    d=nil,
    ftype='afield',
}


local PktField = AField:new{
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
        UINT64=8,
        INT32=4,
        FLOAT=4,
        DOUBLE=8,
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
        DOUBLE='le_float',
    }
}
function PktField:dataWidth()
    local dw = self._data_width[self.t]
    return dw
end
function PktField:rangeGetter()
    return self._data_rng_getter[self.t]
end

local FlagField = AField:new{
    mask=0x00,
    valuestring=nil,
    ftype='flagfield',
}

-- All Packets derive from CbPkt, which defines the packet header
local CbPkt = klass:new{
    name='HEADER',
    fields={
        PktField:new{t='UINT64', n='time', d='Timestamp in tics', format='HEX'},
        PktField:new{t='UINT16', n='chid', format='HEX_DEC'},
        PktField:new{t='UINT8', n='type', format='HEX'},
        PktField:new{t='UINT16', n='dlen', d='Packet Data Length (in quadlets)'},
        PktField:new{t='UINT8', n='instrument', format='HEX'},
        PktField:new{t='UINT16', n='reserved', format='HEX'}
    },
    dfields={},
    pkttypes= setmetatable({}, {__mode="v"}),
    conf_type_map = {[1]=setmetatable({}, {__mode="v"}),
        [2]=setmetatable({}, {__mode="v"})
    },
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
    local types = addfields._types
    addfields._types = nil
    for _, f in pairs(addfields) do
        table.insert(newobj.fields, f)
    end
    for i, f in ipairs(newobj.fields) do
        newobj.fields[f.n] = f
    end

    newobj.fields['type'].valuestring = types

    self.pkttypes[name] = newobj
    setmetatable(newobj, self)
    self.__index = self

    if newobj._kind == 1 or newobj._kind == 2 then
        for k,_ in pairs(newobj.fields['type'].valuestring) do
            self.conf_type_map[newobj._kind][k] = newobj
        end
    end
    return newobj
end
function CbPkt:match(chid, type)
    -- this matches all config packets, i.e. ones where chid==0x8000
    if chid == self._conf_pkg_ch and type ~= nil and self.conf_type_map[1][type] ~= nil then
        return self.conf_type_map[1][type]
    end
    if (chid & self._conf_pkg_ch) == self._conf_pkg_ch and
        (chid & ~(self._conf_pkg_ch)) > 0 and
        type ~= nil and
        self.conf_type_map[2][type] ~= nil then
        return self.conf_type_map[2][type]
    end

    if chid == 0x000 and self.pkttypes.cbPKT_GROUP ~= nil then
        return self.pkttypes.cbPKT_GROUP
    end

    if chid > 0x0000 and chid < cbConst.cbPKT_SPKCACHELINECNT  and self.pkttypes.nevPKT_GENERIC ~= nil then
        return self.pkttypes.nevPKT_GENERIC
    end

    if (cbConst.cbFIRST_DIGIN_CHAN < chid) and (chid <= cbConst.cbFIRST_DIGIN_CHAN+cbConst.cbNUM_DIGIN_CHANS) and self.pkttypes.nevPKT_DIGIN ~= nil then
        return self.pkttypes.nevPKT_DIGIN
    end

    return self.pkttypes['cbPKT_GENERIC']
end

function CbPkt:iterate(b_len)
    local i=0
    local n=#self.fields
    local buf_pos=0
    -- store how many bytes we expect in total. That's composed of 8 header bytes and the reported 'dlen'
    local dlen

    return function()
        i = i + 1
        if i <= n then
            local f = self.fields[i]
            if f.ftype=='afield' or f.ftype=='flagfield' then
                return i, buf_pos, 0, f, 1
            end

            -- if dlen hasn't been read yet, test if it is available, read it from field; add header size
            if dlen == nil and self.dfields['dlen'] ~= nil and self.dfields['dlen']() ~= nil then
                dlen =  16 + self.dfields['dlen']()() * 4
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

function CbPkt:makeInfoString()
    return self.name
end

-- Subclass for config packets. They all share that
-- chid == 0x8000 and 'type' corresponds to a packet type, which we store in the 'type' field's valuestring
local CbPktConfig = CbPkt:new('cb_cfg')
CbPktConfig._kind = 1

-- Subclass for preview stream packets. They all share that
-- (chid & 0x8000) == 0x8000 and (chid&0x0FFF) > 0 and 'type' corresponds to a packet type, which we store in the 'type' field's valuestring
local CbPktPrevStreamBase = CbPkt:new('cb_prev')
CbPktPrevStreamBase._kind = 2

-- Packet definitions start here

-- Generic packets

local CbPktGeneric = CbPkt:new('cbPKT_GENERIC',
    {
        PktField:new{t='BYTES', n='data', lf='dlen', lfactor=4},
    }
)

-- Config packets (chid == 0x8000)

-- System heartbeat
local CbPktSysHeartbeat = CbPktConfig:new('cbPKT_SYSHEARTBEAT', {
    _types={
        [0x00] = "System Heartbeat cbPKTTYPE_SYSHEARTBEAT",
    }
})

-- System protocol monitor
local CbPktSysProtocolMonitor = CbPktConfig:new('cbPKT_SYSPROTOCOLMONITOR',
    {
        PktField:new{t='UINT32', n='sentpkts', d='Packets sent since last cbPKT_SYSPROTOCOLMONITOR (or 0 if timestamp=0)'},
        _types={
            [0x01] = "System Protocol Monitor Packet",
        }
    }
)

-- System condition report packet
local CbPktSysInfo = CbPktConfig:new('cbPKT_SYSINFO',
    {
        PktField:new{t='UINT32', n='sysfreq', d='System clock frequency in Hz', format='DEC'},
        PktField:new{t='UINT32', n='spikelen', d='The length of the spike events', format='DEC'},
        PktField:new{t='UINT32', n='spikepre', d='Spike pre-trigger samples', format='DEC'},
        PktField:new{t='UINT32', n='resetque', d='The channel for the reset to que on', format='DEC'},
        PktField:new{t='UINT32', n='runlevel', d='System runlevel', format='DEC_HEX'},
        PktField:new{t='UINT32', n='runflags', d='Run Flags', format='HEX'},
        _types={
            [0x10] = "System Condition Report cbPKTTYPE_SYSREP",
            [0x11] = "System Spike Length Report cbPKTTYPE_SYSREPSPKLEN",
            [0x12] = "System Runlevel Report cbPKTTYPE_SYSREPRUNLEV",
            [0x90] = "System set Req cbPKTTYPE_SYSSET",
            [0x91] = "System set Spike Length cbPKTTYPE_SYSSETSPKLEN",
            [0x92] = "System set Runlevel cbPKTTYPE_SYSSETRUNLEV",
        }
    }
)

-- System condition report packet
local CbPktSSModelSet = CbPktConfig:new('cbPKT_SS_MODELSET',
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
        _types={
            [0x51] = "SS Model response cbPKTTYPE_SS_MODELREP",
            [0xD1] = "SS Model request cbPKTTYPE_SS_MODELSET",
        }
    }
)

-- NTrode Information Packets
local CbPktNTrodeInfo = CbPktConfig:new('cbPKT_NTRODEINFO',
    {
        PktField:new{t='UINT32', n='ntrode', d='nTrode being configured (1-based)', format='DEC'},
        PktField:new{t='STRING', n='label', d='nTrode label', len=cbConst.cbLEN_STR_LABEL},
        AField:new{n='placeholder', d='→ Other fields of this packet have not been implemented yet. ←'},
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
        _types={
            [0x27] = "NTrode info response cbPKTTYPE_REPNTRODEINFO",
            [0xA7] = "NTrode info request cbPKTTYPE_SETNTRODEINFO",
        }
    }
)

-- Channel Information Packets
local CbPktChanInfo = CbPktConfig:new('cbPKT_CHANINFO',
    {
        PktField:new{t='UINT32', n='chan', d='channel being configured', format='DEC'},
        PktField:new{t='UINT32', n='proc', d='address of the processor', format='DEC'},
        PktField:new{t='UINT32', n='bank', d='address of the bank', format='DEC'},
        PktField:new{t='UINT32', n='term', d='terminal number', format='DEC_HEX'},

        PktField:new{t='UINT32', n='chancaps', d='channel capabilities', format='HEX'},
        FlagField:new{t='BOOLEAN', n='chancaps.exists', format=32, mask=0x00000001, d='cbCHAN_EXISTS id is allocated', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='chancaps.connected', format=32, mask=0x00000002, d='cbCHAN_CONNECTED connected and mapped and ready to use', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='chancaps.isolated', format=32, mask=0x00000004, d='cbCHAN_ISOLATED electrically isolated', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='chancaps.ainp', format=32, mask=0x00000100, d='cbCHAN_AINP analog input capabilities', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='chancaps.aout', format=32, mask=0x00000200, d='cbCHAN_AOUT analog output capabilities', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='chancaps.dinp', format=32, mask=0x00000400, d='cbCHAN_DINP digital input capabilities', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='chancaps.dout', format=32, mask=0x00000800, d='cbCHAN_DOUT digital output capabilities', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='chancaps.gyro', format=32, mask=0x00001000, d='cbCHAN_GYRO gyroscope/accelerometer/magnetometer/temperature capabilities', valuestring={'yes', 'no'}},

        PktField:new{t='UINT32', n='doutcaps', d='digital output capabilities', format='HEX'},
        FlagField:new{t='BOOLEAN', n='doutcaps.serialmask', format=32, mask=0x000000FF, d='cbDOUT_SERIALMASK Port operates as an RS232 Serial Connection', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutcaps.baud2400', format=32, mask=0x00000001, d='cbDOUT_BAUD2400 Serial Port operates at 2400   (n-8-1)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutcaps.baud9600', format=32, mask=0x00000002, d='cbDOUT_BAUD9600 Serial Port operates at 9600   (n-8-1)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutcaps.baud19200', format=32, mask=0x00000004, d='cbDOUT_BAUD19200 Serial Port operates at 19200  (n-8-1)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutcaps.baud38400', format=32, mask=0x00000008, d='cbDOUT_BAUD38400 Serial Port operates at 38400  (n-8-1)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutcaps.baud57600', format=32, mask=0x00000010, d='cbDOUT_BAUD57600 Serial Port operates at 57600  (n-8-1)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutcaps.baud115200', format=32, mask=0x00000020, d='cbDOUT_BAUD115200 Serial Port operates at 115200 (n-8-1)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutcaps.1bit', format=32, mask=0x00000100, d='cbDOUT_1BIT Port has a single output bit (eg single BNC output)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutcaps.8bit', format=32, mask=0x00000200, d='cbDOUT_8BIT Port has 8 output bits', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutcaps.16bit', format=32, mask=0x00000400, d='cbDOUT_16BIT Port has 16 output bits', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutcaps.32bit', format=32, mask=0x00000800, d='cbDOUT_32BIT Port has 32 output bits', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutcaps.value', format=32, mask=0x00010000, d='cbDOUT_VALUE Port can be manually configured', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutcaps.track', format=32, mask=0x00020000, d='cbDOUT_TRACK Port should track the most recently selected channel', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutcaps.frequency', format=32, mask=0x00040000, d='cbDOUT_FREQUENCY Port can output a frequency', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutcaps.triggered', format=32, mask=0x00080000, d='cbDOUT_TRIGGERED Port can be triggered', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutcaps.monitor_unit0', format=32, mask=0x01000000, d='cbDOUT_MONITOR_UNIT0 Can monitor unit 0 = UNCLASSIFIED', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutcaps.monitor_unit1', format=32, mask=0x02000000, d='cbDOUT_MONITOR_UNIT1 Can monitor unit 1', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutcaps.monitor_unit2', format=32, mask=0x04000000, d='cbDOUT_MONITOR_UNIT2 Can monitor unit 2', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutcaps.monitor_unit3', format=32, mask=0x08000000, d='cbDOUT_MONITOR_UNIT3 Can monitor unit 3', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutcaps.monitor_unit4', format=32, mask=0x10000000, d='cbDOUT_MONITOR_UNIT4 Can monitor unit 4', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutcaps.monitor_unit5', format=32, mask=0x20000000, d='cbDOUT_MONITOR_UNIT5 Can monitor unit 5', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutcaps.monitor_unit_all', format=32, mask=0x3F000000, d='cbDOUT_MONITOR_UNIT_ALL Can monitor ALL units', valuestring={'yes', 'no'}},

        PktField:new{t='UINT32', n='dinpcaps', d='digital input capablities', format='HEX'},
        FlagField:new{t='BOOLEAN', n='dinpcaps.serialmask', format=32, mask=0x000000FF, d='cbDINP_SERIALMASK Bit mask used to detect RS232 Serial Baud Rates', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpcaps.baud2400', format=32, mask=0x00000001, d='cbDINP_BAUD2400 RS232 Serial Port operates at 2400   (n-8-1)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpcaps.baud9600', format=32, mask=0x00000002, d='cbDINP_BAUD9600 RS232 Serial Port operates at 9600   (n-8-1)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpcaps.baud19200', format=32, mask=0x00000004, d='cbDINP_BAUD19200 RS232 Serial Port operates at 19200  (n-8-1)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpcaps.baud38400', format=32, mask=0x00000008, d='cbDINP_BAUD38400 RS232 Serial Port operates at 38400  (n-8-1)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpcaps.baud57600', format=32, mask=0x00000010, d='cbDINP_BAUD57600 RS232 Serial Port operates at 57600  (n-8-1)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpcaps.baud115200', format=32, mask=0x00000020, d='cbDINP_BAUD115200 RS232 Serial Port operates at 115200 (n-8-1)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpcaps.1bit', format=32, mask=0x00000100, d='cbDINP_1BIT Port has a single input bit (eg single BNC input)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpcaps.8bit', format=32, mask=0x00000200, d='cbDINP_8BIT Port has 8 input bits', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpcaps.16bit', format=32, mask=0x00000400, d='cbDINP_16BIT Port has 16 input bits', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpcaps.32bit', format=32, mask=0x00000800, d='cbDINP_32BIT Port has 32 input bits', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpcaps.anybit', format=32, mask=0x00001000, d='cbDINP_ANYBIT Capture the port value when any bit changes.', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpcaps.wrdstrb', format=32, mask=0x00002000, d='cbDINP_WRDSTRB Capture the port when a word-write line is strobed', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpcaps.pktchar', format=32, mask=0x00004000, d='cbDINP_PKTCHAR Capture packets using an End of Packet Character', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpcaps.pktstrb', format=32, mask=0x00008000, d='cbDINP_PKTSTRB Capture packets using an End of Packet Logic Input', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpcaps.monitor', format=32, mask=0x00010000, d='cbDINP_MONITOR Port controls other ports or system events', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpcaps.redge', format=32, mask=0x00020000, d='cbDINP_REDGE Capture the port value when any bit changes lo-2-hi (rising edge)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpcaps.fedge', format=32, mask=0x00040000, d='cbDINP_FEDGE Capture the port value when any bit changes hi-2-lo (falling edge)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpcaps.strbany', format=32, mask=0x00080000, d='cbDINP_STRBANY Capture packets using 8-bit strobe/8-bit any Input', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpcaps.strbris', format=32, mask=0x00100000, d='cbDINP_STRBRIS Capture packets using 8-bit strobe/8-bit rising edge Input', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpcaps.strbfal', format=32, mask=0x00200000, d='cbDINP_STRBFAL Capture packets using 8-bit strobe/8-bit falling edge Input', valuestring={'yes', 'no'}},

        PktField:new{t='UINT32', n='aoutcaps', d='analog output capablities', format='HEX'},
        FlagField:new{t='BOOLEAN', n='aoutcaps.audio', format=32, mask=0x00000001, d='cbAOUT_AUDIO Channel is physically optimized for audio output', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='aoutcaps.scale', format=32, mask=0x00000002, d='cbAOUT_SCALE Output a static value', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='aoutcaps.track', format=32, mask=0x00000004, d='cbAOUT_TRACK Output a static value', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='aoutcaps.static', format=32, mask=0x00000008, d='cbAOUT_STATIC Output a static value', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='aoutcaps.monitorraw', format=32, mask=0x00000010, d='cbAOUT_MONITORRAW Monitor an analog signal line - RAW data', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='aoutcaps.monitorlnc', format=32, mask=0x00000020, d='cbAOUT_MONITORLNC Monitor an analog signal line - Line Noise Cancelation', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='aoutcaps.monitorsmp', format=32, mask=0x00000040, d='cbAOUT_MONITORSMP Monitor an analog signal line - Continuous', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='aoutcaps.monitorspk', format=32, mask=0x00000080, d='cbAOUT_MONITORSPK Monitor an analog signal line - spike', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='aoutcaps.stimulate', format=32, mask=0x00000100, d='cbAOUT_STIMULATE Stimulation waveform functions are available.', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='aoutcaps.waveform', format=32, mask=0x00000200, d='cbAOUT_WAVEFORM Custom Waveform', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='aoutcaps.extension', format=32, mask=0x00000400, d='cbAOUT_EXTENSION Output Waveform from Extension', valuestring={'yes', 'no'}},

        PktField:new{t='UINT32', n='ainpcaps', d='analog input capablities', format='HEX'},
        FlagField:new{t='BOOLEAN', n='ainpcaps.rawpreview', format=32, mask=0x00000001, d='cbAINP_RAWPREVIEW Generate scrolling preview data for the raw channel', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='ainpcaps.lnc', format=32, mask=0x00000002, d='cbAINP_LNC Line Noise Cancellation', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='ainpcaps.lncpreview', format=32, mask=0x00000004, d='cbAINP_LNCPREVIEW Retrieve the LNC correction waveform', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='ainpcaps.smpstream', format=32, mask=0x00000010, d='cbAINP_SMPSTREAM stream the analog input stream directly to disk', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='ainpcaps.smpfilter', format=32, mask=0x00000020, d='cbAINP_SMPFILTER Digitally filter the analog input stream', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='ainpcaps.rawstream', format=32, mask=0x00000040, d='cbAINP_RAWSTREAM Raw data stream available', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='ainpcaps.spkstream', format=32, mask=0x00000100, d='cbAINP_SPKSTREAM Spike Stream is available', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='ainpcaps.spkfilter', format=32, mask=0x00000200, d='cbAINP_SPKFILTER Selectable Filters', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='ainpcaps.spkpreview', format=32, mask=0x00000400, d='cbAINP_SPKPREVIEW Generate scrolling preview of the spike channel', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='ainpcaps.spkproc', format=32, mask=0x00000800, d='cbAINP_SPKPROC Channel is able to do online spike processing', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='ainpcaps.offset_correct_cap', format=32, mask=0x00001000, d='cbAINP_OFFSET_CORRECT_CAP Offset correction mode (0-disabled 1-enabled)', valuestring={'yes', 'no'}},

        PktField:new{t='UINT32', n='spkcaps', d='spike capablities', format='HEX'},
        FlagField:new{t='BOOLEAN', n='spkcaps.extract', format=32, mask=0x00000001, d='cbAINPSPK_EXTRACT time-stamp and packet to first superthreshold peak', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkcaps.rejart', format=32, mask=0x00000002, d='cbAINPSPK_REJART Reject around clipped signals on multiple channels', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkcaps.rejclip', format=32, mask=0x00000004, d='cbAINPSPK_REJCLIP Reject clipped signals on the channel', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkcaps.alignpk', format=32, mask=0x00000008, d='cbAINPSPK_ALIGNPK', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkcaps.rejampl', format=32, mask=0x00000010, d='cbAINPSPK_REJAMPL Reject based on amplitude', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkcaps.thrlevel', format=32, mask=0x00000100, d='cbAINPSPK_THRLEVEL Analog level threshold detection', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkcaps.threnergy', format=32, mask=0x00000200, d='cbAINPSPK_THRENERGY Energy threshold detection', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkcaps.thrauto', format=32, mask=0x00000400, d='cbAINPSPK_THRAUTO Auto threshold detection', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkcaps.spreadsort', format=32, mask=0x00001000, d='cbAINPSPK_SPREADSORT Enable auto spread sorting', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkcaps.corrsort', format=32, mask=0x00002000, d='cbAINPSPK_CORRSORT Enable auto histogram correlation sorting', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkcaps.peakmajsort', format=32, mask=0x00004000, d='cbAINPSPK_PEAKMAJSORT Enable auto histogram peak major sorting', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkcaps.peakfishsort', format=32, mask=0x00008000, d='cbAINPSPK_PEAKFISHSORT Enable auto histogram peak fisher sorting', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkcaps.hoopsort', format=32, mask=0x00010000, d='cbAINPSPK_HOOPSORT Enable manual hoop sorting', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkcaps.pcamansort', format=32, mask=0x00020000, d='cbAINPSPK_PCAMANSORT Enable manual PCA sorting', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkcaps.pcakmeansort', format=32, mask=0x00040000, d='cbAINPSPK_PCAKMEANSORT Enable k-means PCA sorting', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkcaps.pcaemsort', format=32, mask=0x00080000, d='cbAINPSPK_PCAEMSORT Enable EM-clustering PCA sorting', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkcaps.pcadbsort', format=32, mask=0x00100000, d='cbAINPSPK_PCADBSORT Enable DBSCAN PCA sorting', valuestring={'yes', 'no'}},

        AField:new{n='physcalin', d='physical channel scaling information (in)'},
        PktField:new{t='INT16', n='physcalin.digmin', d='digital value that cooresponds with the anamin value'},
        PktField:new{t='INT16', n='physcalin.digmax', d='digital value that cooresponds with the anamax value'},
        PktField:new{t='INT32', n='physcalin.anamin', d='minimum analog value present in the signal'},
        PktField:new{t='INT32', n='physcalin.anamax', d='maximum analog value present in the signal'},
        PktField:new{t='INT32', n='physcalin.anagain', d='gain applied to the default analog values to get the analog values'},
        PktField:new{t='STRING', n='physcalin.anaunit', d='nTrode label', len=cbConst.cbLEN_STR_UNIT},

        AField:new{n='phyfiltin', d='physical channel filter definition (in)'},
        PktField:new{t='STRING', n='phyfiltin.label', d='filter label', len=cbConst.cbLEN_STR_FILT_LABEL},
        PktField:new{t='UINT32', n='phyfiltin.hpfreq', d='high-pass corner frequency in milliHertz'},
        PktField:new{t='UINT32', n='phyfiltin.hporder', d='high-pass filter order'},
        PktField:new{t='UINT32', n='phyfiltin.hptype', d='high-pass filter type', format='HEX'},
        PktField:new{t='UINT32', n='phyfiltin.lpfreq', d='low-pass frequency in milliHertz'},
        PktField:new{t='UINT32', n='phyfiltin.lporder', d='low-pass filter order'},
        PktField:new{t='UINT32', n='phyfiltin.lptype', d='low-pass filter type', format='HEX'},

        AField:new{n='physcalout', d='physical channel scaling information (out)'},
        PktField:new{t='INT16', n='physcalout.digmin', d='digital value that cooresponds with the anamin value'},
        PktField:new{t='INT16', n='physcalout.digmax', d='digital value that cooresponds with the anamax value'},
        PktField:new{t='INT32', n='physcalout.anamin', d='minimum analog value present in the signal'},
        PktField:new{t='INT32', n='physcalout.anamax', d='maximum analog value present in the signal'},
        PktField:new{t='INT32', n='physcalout.anagain', d='gain applied to the default analog values to get the analog values'},
        PktField:new{t='STRING', n='physcalin.anaunit', d='nTrode label', len=cbConst.cbLEN_STR_UNIT},

        AField:new{n='phyfiltout', d='physical channel filter definition (out)'},
        PktField:new{t='STRING', n='phyfiltout.label', d='filter label', len=cbConst.cbLEN_STR_FILT_LABEL},
        PktField:new{t='UINT32', n='phyfiltout.hpfreq', d='high-pass corner frequency in milliHertz'},
        PktField:new{t='UINT32', n='phyfiltout.hporder', d='high-pass filter order'},
        PktField:new{t='UINT32', n='phyfiltout.hptype', d='high-pass filter type', format='HEX'},
        PktField:new{t='UINT32', n='phyfiltout.lpfreq', d='low-pass frequency in milliHertz'},
        PktField:new{t='UINT32', n='phyfiltout.lporder', d='low-pass filter order'},
        PktField:new{t='UINT32', n='phyfiltout.lptype', d='low-pass filter type', format='HEX'},

        PktField:new{t='STRING', n='label', d='label', len=cbConst.cbLEN_STR_LABEL},
        PktField:new{t='UINT32', n='userflags', format='HEX'},
        PktField:new{t='INT32', n='position', len=4},

        AField:new{n='scalin', d='scaling information (in)'},
        PktField:new{t='INT16', n='scalin.digmin', d='digital value that cooresponds with the anamin value'},
        PktField:new{t='INT16', n='scalin.digmax', d='digital value that cooresponds with the anamax value'},
        PktField:new{t='INT32', n='scalin.anamin', d='minimum analog value present in the signal'},
        PktField:new{t='INT32', n='scalin.anamax', d='maximum analog value present in the signal'},
        PktField:new{t='INT32', n='scalin.anagain', d='gain applied to the default analog values to get the analog values'},
        PktField:new{t='STRING', n='scalin.anaunit', d='nTrode label', len=cbConst.cbLEN_STR_UNIT},

        AField:new{n='scalout', d='scaling information (out)'},
        PktField:new{t='INT16', n='scalout.digmin', d='digital value that cooresponds with the anamin value'},
        PktField:new{t='INT16', n='scalout.digmax', d='digital value that cooresponds with the anamax value'},
        PktField:new{t='INT32', n='scalout.anamin', d='minimum analog value present in the signal'},
        PktField:new{t='INT32', n='scalout.anamax', d='maximum analog value present in the signal'},
        PktField:new{t='INT32', n='scalout.anagain', d='gain applied to the default analog values to get the analog values'},
        PktField:new{t='STRING', n='scalout.anaunit', d='nTrode label', len=cbConst.cbLEN_STR_UNIT},

        PktField:new{t='UINT32', n='doutopts', d='digital output options', format='HEX'},
        FlagField:new{t='BOOLEAN', n='doutopts.serialmask', format=32, mask=0x000000FF, d='cbDOUT_SERIALMASK Port operates as an RS232 Serial Connection', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutopts.baud2400', format=32, mask=0x00000001, d='cbDOUT_BAUD2400 Serial Port operates at 2400   (n-8-1)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutopts.baud9600', format=32, mask=0x00000002, d='cbDOUT_BAUD9600 Serial Port operates at 9600   (n-8-1)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutopts.baud19200', format=32, mask=0x00000004, d='cbDOUT_BAUD19200 Serial Port operates at 19200  (n-8-1)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutopts.baud38400', format=32, mask=0x00000008, d='cbDOUT_BAUD38400 Serial Port operates at 38400  (n-8-1)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutopts.baud57600', format=32, mask=0x00000010, d='cbDOUT_BAUD57600 Serial Port operates at 57600  (n-8-1)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutopts.baud115200', format=32, mask=0x00000020, d='cbDOUT_BAUD115200 Serial Port operates at 115200 (n-8-1)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutopts.1bit', format=32, mask=0x00000100, d='cbDOUT_1BIT Port has a single output bit (eg single BNC output)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutopts.8bit', format=32, mask=0x00000200, d='cbDOUT_8BIT Port has 8 output bits', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutopts.16bit', format=32, mask=0x00000400, d='cbDOUT_16BIT Port has 16 output bits', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutopts.32bit', format=32, mask=0x00000800, d='cbDOUT_32BIT Port has 32 output bits', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutopts.value', format=32, mask=0x00010000, d='cbDOUT_VALUE Port can be manually configured', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutopts.track', format=32, mask=0x00020000, d='cbDOUT_TRACK Port should track the most recently selected channel', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutopts.frequency', format=32, mask=0x00040000, d='cbDOUT_FREQUENCY Port can output a frequency', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutopts.triggered', format=32, mask=0x00080000, d='cbDOUT_TRIGGERED Port can be triggered', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutopts.monitor_unit0', format=32, mask=0x01000000, d='cbDOUT_MONITOR_UNIT0 Can monitor unit 0 = UNCLASSIFIED', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutopts.monitor_unit1', format=32, mask=0x02000000, d='cbDOUT_MONITOR_UNIT1 Can monitor unit 1', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutopts.monitor_unit2', format=32, mask=0x04000000, d='cbDOUT_MONITOR_UNIT2 Can monitor unit 2', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutopts.monitor_unit3', format=32, mask=0x08000000, d='cbDOUT_MONITOR_UNIT3 Can monitor unit 3', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutopts.monitor_unit4', format=32, mask=0x10000000, d='cbDOUT_MONITOR_UNIT4 Can monitor unit 4', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutopts.monitor_unit5', format=32, mask=0x20000000, d='cbDOUT_MONITOR_UNIT5 Can monitor unit 5', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='doutopts.monitor_unit_all', format=32, mask=0x3F000000, d='cbDOUT_MONITOR_UNIT_ALL Can monitor ALL units', valuestring={'yes', 'no'}},

        PktField:new{t='UINT32', n='dinpopts', d='digital input options', format='HEX'},
        FlagField:new{t='BOOLEAN', n='dinpopts.serialmask', format=32, mask=0x000000FF, d='cbDINP_SERIALMASK Bit mask used to detect RS232 Serial Baud Rates', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpopts.baud2400', format=32, mask=0x00000001, d='cbDINP_BAUD2400 RS232 Serial Port operates at 2400   (n-8-1)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpopts.baud9600', format=32, mask=0x00000002, d='cbDINP_BAUD9600 RS232 Serial Port operates at 9600   (n-8-1)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpopts.baud19200', format=32, mask=0x00000004, d='cbDINP_BAUD19200 RS232 Serial Port operates at 19200  (n-8-1)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpopts.baud38400', format=32, mask=0x00000008, d='cbDINP_BAUD38400 RS232 Serial Port operates at 38400  (n-8-1)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpopts.baud57600', format=32, mask=0x00000010, d='cbDINP_BAUD57600 RS232 Serial Port operates at 57600  (n-8-1)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpopts.baud115200', format=32, mask=0x00000020, d='cbDINP_BAUD115200 RS232 Serial Port operates at 115200 (n-8-1)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpopts.1bit', format=32, mask=0x00000100, d='cbDINP_1BIT Port has a single input bit (eg single BNC input)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpopts.8bit', format=32, mask=0x00000200, d='cbDINP_8BIT Port has 8 input bits', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpopts.16bit', format=32, mask=0x00000400, d='cbDINP_16BIT Port has 16 input bits', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpopts.32bit', format=32, mask=0x00000800, d='cbDINP_32BIT Port has 32 input bits', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpopts.anybit', format=32, mask=0x00001000, d='cbDINP_ANYBIT Capture the port value when any bit changes.', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpopts.wrdstrb', format=32, mask=0x00002000, d='cbDINP_WRDSTRB Capture the port when a word-write line is strobed', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpopts.pktchar', format=32, mask=0x00004000, d='cbDINP_PKTCHAR Capture packets using an End of Packet Character', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpopts.pktstrb', format=32, mask=0x00008000, d='cbDINP_PKTSTRB Capture packets using an End of Packet Logic Input', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpopts.monitor', format=32, mask=0x00010000, d='cbDINP_MONITOR Port controls other ports or system events', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpopts.redge', format=32, mask=0x00020000, d='cbDINP_REDGE Capture the port value when any bit changes lo-2-hi (rising edge)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpopts.fedge', format=32, mask=0x00040000, d='cbDINP_FEDGE Capture the port value when any bit changes hi-2-lo (falling edge)', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpopts.strbany', format=32, mask=0x00080000, d='cbDINP_STRBANY Capture packets using 8-bit strobe/8-bit any Input', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpopts.strbris', format=32, mask=0x00100000, d='cbDINP_STRBRIS Capture packets using 8-bit strobe/8-bit rising edge Input', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='dinpopts.strbfal', format=32, mask=0x00200000, d='cbDINP_STRBFAL Capture packets using 8-bit strobe/8-bit falling edge Input', valuestring={'yes', 'no'}},

        PktField:new{t='UINT32', n='aoutopts', d='analog output options', format='HEX'},
        FlagField:new{t='BOOLEAN', n='aoutopts.audio', format=32, mask=0x00000001, d='cbAOUT_AUDIO Channel is physically optimized for audio output', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='aoutopts.scale', format=32, mask=0x00000002, d='cbAOUT_SCALE Output a static value', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='aoutopts.track', format=32, mask=0x00000004, d='cbAOUT_TRACK Output a static value', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='aoutopts.static', format=32, mask=0x00000008, d='cbAOUT_STATIC Output a static value', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='aoutopts.monitorraw', format=32, mask=0x00000010, d='cbAOUT_MONITORRAW Monitor an analog signal line - RAW data', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='aoutopts.monitorlnc', format=32, mask=0x00000020, d='cbAOUT_MONITORLNC Monitor an analog signal line - Line Noise Cancelation', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='aoutopts.monitorsmp', format=32, mask=0x00000040, d='cbAOUT_MONITORSMP Monitor an analog signal line - Continuous', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='aoutopts.monitorspk', format=32, mask=0x00000080, d='cbAOUT_MONITORSPK Monitor an analog signal line - spike', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='aoutopts.stimulate', format=32, mask=0x00000100, d='cbAOUT_STIMULATE Stimulation waveform functions are available.', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='aoutopts.waveform', format=32, mask=0x00000200, d='cbAOUT_WAVEFORM Custom Waveform', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='aoutopts.extension', format=32, mask=0x00000400, d='cbAOUT_EXTENSION Output Waveform from Extension', valuestring={'yes', 'no'}},

        PktField:new{t='UINT32', n='eopchar', format='HEX'},
        PktField:new{t='UINT16', n='moninst', format='HEX'},
        PktField:new{t='UINT16', n='monchan', format='HEX'},
        PktField:new{t='INT32', n='outvalue'},

        PktField:new{t='UINT8', n='trigtype'},
        -- Not sure when the next 2 lines were added to protocol. 4.0 or 4.11.
        -- If this breaks 4.0 then delete the next 2 lines.
        PktField:new{t='UINT16', n='reserved'},
        PktField:new{t='UINT8', n='triginst'},
        PktField:new{t='UINT16', n='trigchan'},
        PktField:new{t='UINT16', n='trigval'},

        PktField:new{t='UINT32', n='ainpopts', d='analog input options', format='HEX'},
        FlagField:new{t='BOOLEAN', n='ainpopts.rawpreview', format=32, mask=0x00000001, d='cbAINP_RAWPREVIEW Generate scrolling preview data for the raw channel', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='ainpopts.lnc', format=32, mask=0x00000002, d='cbAINP_LNC Line Noise Cancellation', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='ainpopts.lncpreview', format=32, mask=0x00000004, d='cbAINP_LNCPREVIEW Retrieve the LNC correction waveform', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='ainpopts.smpstream', format=32, mask=0x00000010, d='cbAINP_SMPSTREAM stream the analog input stream directly to disk', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='ainpopts.smpfilter', format=32, mask=0x00000020, d='cbAINP_SMPFILTER Digitally filter the analog input stream', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='ainpopts.rawstream', format=32, mask=0x00000040, d='cbAINP_RAWSTREAM Raw data stream available', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='ainpopts.spkstream', format=32, mask=0x00000100, d='cbAINP_SPKSTREAM Spike Stream is available', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='ainpopts.spkfilter', format=32, mask=0x00000200, d='cbAINP_SPKFILTER Selectable Filters', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='ainpopts.spkpreview', format=32, mask=0x00000400, d='cbAINP_SPKPREVIEW Generate scrolling preview of the spike channel', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='ainpopts.spkproc', format=32, mask=0x00000800, d='cbAINP_SPKPROC Channel is able to do online spike processing', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='ainpopts.offset_cor', format=32, mask=0x00001000, d='cbAINP_OFFSET_CORRECT_CAP Offset correction mode (0-disabled 1-enabled)', valuestring={'yes', 'no'}},

        PktField:new{t='UINT32', n='lncrate'},

        PktField:new{t='UINT32', n='smpfilter'},
        PktField:new{t='UINT32', n='smpgroup'},

        PktField:new{t='INT32', n='smpdispmin'},
        PktField:new{t='INT32', n='smpdispmax'},

        PktField:new{t='UINT32', n='spkfilter'},

        PktField:new{t='INT32', n='spkdispmax'},
        PktField:new{t='INT32', n='lncdispmax'},

        PktField:new{t='UINT32', n='spkopts', d='spike options', format='HEX'},
        FlagField:new{t='BOOLEAN', n='spkopts.extract', format=32, mask=0x00000001, d='cbAINPSPK_EXTRACT time-stamp and packet to first superthreshold peak', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkopts.rejart', format=32, mask=0x00000002, d='cbAINPSPK_REJART Reject around clipped signals on multiple channels', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkopts.rejclip', format=32, mask=0x00000004, d='cbAINPSPK_REJCLIP Reject clipped signals on the channel', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkopts.alignpk', format=32, mask=0x00000008, d='cbAINPSPK_ALIGNPK', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkopts.rejampl', format=32, mask=0x00000010, d='cbAINPSPK_REJAMPL Reject based on amplitude', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkopts.thrlevel', format=32, mask=0x00000100, d='cbAINPSPK_THRLEVEL Analog level threshold detection', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkopts.threnergy', format=32, mask=0x00000200, d='cbAINPSPK_THRENERGY Energy threshold detection', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkopts.thrauto', format=32, mask=0x00000400, d='cbAINPSPK_THRAUTO Auto threshold detection', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkopts.spreadsort', format=32, mask=0x00001000, d='cbAINPSPK_SPREADSORT Enable auto spread sorting', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkopts.corrsort', format=32, mask=0x00002000, d='cbAINPSPK_CORRSORT Enable auto histogram correlation sorting', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkopts.peakmajsort', format=32, mask=0x00004000, d='cbAINPSPK_PEAKMAJSORT Enable auto histogram peak major sorting', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkopts.peakfishsort', format=32, mask=0x00008000, d='cbAINPSPK_PEAKFISHSORT Enable auto histogram peak fisher sorting', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkopts.hoopsort', format=32, mask=0x00010000, d='cbAINPSPK_HOOPSORT Enable manual hoop sorting', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkopts.pcamansort', format=32, mask=0x00020000, d='cbAINPSPK_PCAMANSORT Enable manual PCA sorting', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkopts.pcakmeansort', format=32, mask=0x00040000, d='cbAINPSPK_PCAKMEANSORT Enable k-means PCA sorting', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkopts.pcaemsort', format=32, mask=0x00080000, d='cbAINPSPK_PCAEMSORT Enable EM-clustering PCA sorting', valuestring={'yes', 'no'}},
        FlagField:new{t='BOOLEAN', n='spkopts.pcadbsort', format=32, mask=0x00100000, d='cbAINPSPK_PCADBSORT Enable DBSCAN PCA sorting', valuestring={'yes', 'no'}},

        PktField:new{t='INT32', n='spkthrlevel'},
        PktField:new{t='INT32', n='spkthrlimit'},

        PktField:new{t='UINT32', n='spkgroup'},

        PktField:new{t='INT16', n='amplrejpos'},
        PktField:new{t='INT16', n='amplrejneg'},
        PktField:new{t='UINT32', n='refelecchan'},

        AField:new{n='placeholder', d='→ Other fields [unitmapping, spkhoops] of this packet have not been implemented yet. ←'},

        _types={
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
    }
)

-- File Config Information Packets
local CbPktFileCfg = CbPktConfig:new('cbPKT_FILECFG',
    {
        PktField:new{t='UINT32', n='options', d='File Config Option', format='HEX', valuestring={
            [0x00]="Launch File dialog, set file info, start or stop recording cbFILECFG_OPT_NONE",
            [0x01]="Keep-alive message cbFILECFG_OPT_KEEPALIVE",
            [0x02]="Recording is in progress cbFILECFG_OPT_REC",
            [0x03]="Recording stopped cbFILECFG_OPT_STOP",
            [0x04]="NeuroMotive recording status cbFILECFG_OPT_NMREC",
            [0x05]="Close file application cbFILECFG_OPT_CLOSE",
            [0x06]="Recording datetime cbFILECFG_OPT_SYNCH",
            [0x07]="Launch File dialog, do not set or do anything cbFILECFG_OPT_OPEN",
        }},
        -- FlagField:new{t='BOOLEAN', n='options.keepalive', format=32, mask=0x00000001, d='Keep-alive message cbFILECFG_OPT_KEEPALIVE', valuestring={'yes', 'no'}},
        -- FlagField:new{t='BOOLEAN', n='options.rec', format=32, mask=0x00000002, d='Recording is in progress cbFILECFG_OPT_REC', valuestring={'yes', 'no'}},
        -- FlagField:new{t='BOOLEAN', n='options.stop', format=32, mask=0x00000002, d='Recording is in progress cbFILECFG_OPT_REC', valuestring={'yes', 'no'}},
        PktField:new{t='UINT32', n='duration', format='DEC'},
        PktField:new{t='UINT32', n='recording', d='If cbFILECFG_OPT_NONE this option starts/stops recording remotely', format='HEX'},
        PktField:new{t='UINT32', n='extctrl', d='If cbFILECFG_OPT_REC this is split number (0 for non-TOC). If cbFILECFG_OPT_STOP this is error code.', format='DEC_HEX'},
        PktField:new{t='STRING', n='username', len=256},
        PktField:new{t='STRING', n='filename', len=256},
        PktField:new{t='STRING', n='comment', len=256, d='Comment or Datetime'},
        _types={
            [0x61] = "File Config response cbPKTTYPE_REPFILECFG",
            [0xE1] = "File Config request cbPKTTYPE_SETFILECFG",
        }
    }
)

-- Config All packet
local CbPktConfigAll = CbPktConfig:new('cbPKT_CONFIGALL', {_types={
    [0x08] = "Config All Report cbPKTTYPE_REPCONFIGALL",
    [0x88] = "Config All Request cbPKTTYPE_REQCONFIGALL",
    }})

-- Options for noise boundary packets
local CbPktSSNoiseBoundary = CbPktConfig:new('cbPKT_SS_NOISE_BOUNDARY',
    {
        PktField:new{t='UINT32', n='chan', d='channel being configured', format='DEC'},
        PktField:new{t='FLOAT', n='afc', len=3, d='Center of ellipsoid'},
        PktField:new{t='FLOAT', n='afS', len=9, d='Ellipsoid axes'},
        _types={
            [0x54] = "Noise boundary Report cbPKTTYPE_SS_NOISE_BOUNDARYREP",
            [0xD4] = "Noise boundary Request cbPKTTYPE_SS_NOISE_BOUNDARYSET",
        }
    }
)

-- SS Statistics packets
local CbPktSSStatistics = CbPktConfig:new('cbPKT_SS_STATISTICS',
    {
        PktField:new{t='UINT32', n='nUpdateSpikes', d='update rate in spike counts', format='DEC'},
        PktField:new{t='UINT32', n='nAutoalg', d='Sorting Algorithm', format='HEX', valuestring={
            [0x00]="No sorting cbAUTOALG_NONE",
            [0x01]="Auto spread cbAUTOALG_SPREAD",
            [0x02]="Auto Hist Correlation cbAUTOALG_HIST_CORR_MAJ",
            [0x03]="Auto Hist Peak Maj cbAUTOALG_HIST_PEAK_COUNT_MAJ",
            [0x04]="Auto Hist Peak Fish cbAUTOALG_HIST_PEAK_COUNT_FISH",
            [0x05]="Manual PCA cbAUTOALG_PCA",
            [0x06]="Manual Hoops cbAUTOALG_HOOPS",
            [0x07]="K-means PCA cbAUTOALG_PCA_KMEANS",
            [0x08]="EM-clustering PCA cbAUTOALG_PCA_EM",
            [0x09]="DBSCAN PCA cbAUTOALG_PCA_DBSCAN",
        }},
        PktField:new{t='UINT32', n='nMode', d='command to change sorting parameters', format='HEX', valuestring={
            [0x00]="Change the settings and leave sorting the same cbAUTOALG_MODE_SETTING",
            [0x01]="Change settings and apply this sorting to all channels cbAUTOALG_MODE_APPLY",
        }},
        PktField:new{t='FLOAT', n='fMinClusterPairSpreadFactor'},
        PktField:new{t='FLOAT', n='fMaxSubclusterSpreadFactor'},

        PktField:new{t='FLOAT', n='fMinClusterHistCorrMajMeasure'},
        PktField:new{t='FLOAT', n='fMaxClusterPairHistCorrMajMeasure'},

        PktField:new{t='FLOAT', n='fClusterHistValleyPercentage'},
        PktField:new{t='FLOAT', n='fClusterHistClosePeakPercentage'},
        PktField:new{t='FLOAT', n='fClusterHistMinPeakPercentage'},
        PktField:new{t='UINT32', n='nWaveBasisSize', d='number of wave to collect to calculate the basis', format='DEC'},
        PktField:new{t='UINT32', n='nWaveSampleSize', d='number of samples sorted with the same basis before re-calculating the basis', format='DEC'},
        _types={
            [0x55] = "SS Statistics Report cbPKTTYPE_SS_STATISTICSREP",
            [0xD5] = "SS Statistics Request cbPKTTYPE_SS_STATISTICSSET",
        }
    }
)

-- SS Status packets
local CbPktSSStatus = CbPktConfig:new('cbPKT_SS_STATUS',
    {
        AField:new{n='cntlUnitStats'},
        PktField:new{t='UINT32', n='cntlUnitStats.nMode', d='nMode', format='HEX', valuestring={
            [0x00]="do not adapt at all",
            [0x01]="always adapt",
            [0x02]="adapt if timer not timed out",
        }},
        PktField:new{t='FLOAT', n='cntlUnitStats.fTimeOutMinutes', d='how many minutes until time out'},
        PktField:new{t='FLOAT', n='cntlUnitStats.fElapsedMinutes', d='amount of time that has elapsed'},
        AField:new{n='cntlNumUnits'},
        PktField:new{t='UINT32', n='cntlNumUnits.nMode', d='nMode', format='HEX', valuestring={
            [0x00]="do not adapt at all",
            [0x01]="always adapt",
            [0x02]="adapt if timer not timed out",
        }},
        PktField:new{t='FLOAT', n='cntlNumUnits.fTimeOutMinutes', d='how many minutes until time out'},
        PktField:new{t='FLOAT', n='cntlNumUnits.fElapsedMinutes', d='amount of time that has elapsed'},
        _types={
            [0x57] = "SS Status Report cbPKTTYPE_SS_STATUSREP",
            [0xD7] = "SS Status Request cbPKTTYPE_SS_STATUSSET",
        }
    }
)

-- SS Recalc packets
local CbPktSSRecalc = CbPktConfig:new('cbPKT_SS_RECALC',
    {

        PktField:new{t='UINT32', n='chan',format='DEC', d="Channel (1-based). If 0, perform for all"},
        PktField:new{t='UINT32', n='mode', d='mode', format='HEX', valuestring={
            [0]="PC ->NSP start recalculation cbPCA_RECALC_START",
            [1]="NSP->PC  finished recalculation cbPCA_RECALC_STOPPED",
            [2]="NSP->PC  waveform collection started cbPCA_COLLECTION_STARTED",
            [3]="Change the basis of feature space cbBASIS_CHANGE",
            [4]="cbUNDO_BASIS_CHANGE",
            [5]="cbREDO_BASIS_CHANGE",
            [6]="cbINVALIDATE_BASIS",
        }},
        _types={
            [0x59] = "SS Recalc Report cbPKTTYPE_SS_RECALCREP",
            [0xD9] = "SS Recalc Request cbPKTTYPE_SS_RECALCSET",
        }
    }
)

-- Feature Space Basis Packets
local CbPktFSBasis = CbPktConfig:new('cbPKT_FS_BASIS',
    {

        PktField:new{t='UINT32', n='chan',format='DEC', d="Channel (1-based)"},
        PktField:new{t='UINT32', n='mode', d='mode', format='HEX', valuestring={
            [0]="PC ->NSP start recalculation cbPCA_RECALC_START",
            [1]="NSP->PC  finished recalculation cbPCA_RECALC_STOPPED",
            [2]="NSP->PC  waveform collection started cbPCA_COLLECTION_STARTED",
            [3]="Change the basis of feature space cbBASIS_CHANGE",
            [4]="cbUNDO_BASIS_CHANGE",
            [5]="cbREDO_BASIS_CHANGE",
            [6]="cbINVALIDATE_BASIS",
        }},
        PktField:new{t='UINT32', n='fs',format='DEC', d="Feature space: cbAUTOALG_PCA"},
        PktField:new{t='FLOAT', n='basis', d='Room for all possible points collected'},
        AField:new{n='notImpl', d="→ Variable number of points not imlpemented ←"},
        _types={
            [0x5B] = "FS Basis Report cbPKTTYPE_FS_BASISREP",
            [0xDB] = "FS Basis Request cbPKTTYPE_FS_BASISSET",
        }
    }
)


-- Sample Group Information packets
local CbPktGroupInfo = CbPktConfig:new('cbPKT_GROUPINFO',
    {
        PktField:new{t='UINT32', n='proc',format='DEC'},
        PktField:new{t='UINT32', n='group',format='DEC'},
        PktField:new{t='STRING', n='label', len=cbConst.cbLEN_STR_LABEL},
        PktField:new{t='UINT32', n='period', d='Sampling Period', format='DEC'},
        PktField:new{t='UINT32', n='length', format='DEC'},
        PktField:new{t='UINT32', n='list', lf='length', d='channelList'},
        _types={
            [0x30] = "Sample Group Report cbPKTTYPE_GROUPREP",
            [0xB0] = "Sample Group Request cbPKTTYPE_GROUPSET",
        }
    }
)

-- Processor Information packets
local CbPktProcInfo = CbPktConfig:new('cbPKT_PROCINFO',
    {
        PktField:new{t='UINT32', n='proc',format='DEC'},
        PktField:new{t='UINT32', n='idcode', format='DEC_HEX', d='Manufacturer ID'},
        PktField:new{t='STRING', n='ident', len=cbConst.cbLEN_STR_IDENT},
        PktField:new{t='UINT32', n='chanbase',format='DEC'},
        PktField:new{t='UINT32', n='chancount',format='DEC'},
        PktField:new{t='UINT32', n='bankcount',format='DEC'},
        PktField:new{t='UINT32', n='groupcount',format='DEC'},
        PktField:new{t='UINT32', n='filtcount',format='DEC'},
        PktField:new{t='UINT32', n='sortcount',format='DEC'},
        PktField:new{t='UINT32', n='unitcount',format='DEC'},
        PktField:new{t='UINT32', n='hoopcount',format='DEC'},
        PktField:new{t='UINT32', n='sortmethod',format='DEC', valuestring={[0]='manual', [1]='auto'}},
        PktField:new{t='UINT32', n='version',format='DEC'},
        _types={
    [0x21] = "Proc Report cbPKTTYPE_PROCREP",
    }})

-- Bank Information packets
local CbPktBankInfo = CbPktConfig:new('cbPKT_BANKINFO',
    {
        PktField:new{t='UINT32', n='proc',format='DEC'},
        PktField:new{t='UINT32', n='bank',format='DEC'},
        PktField:new{t='UINT32', n='idcode', format='DEC_HEX', d='Manufacturer ID'},
        PktField:new{t='STRING', n='ident', len=cbConst.cbLEN_STR_IDENT},
        PktField:new{t='STRING', n='label', len=cbConst.cbLEN_STR_LABEL},
        PktField:new{t='UINT32', n='chanbase',format='DEC'},
        PktField:new{t='UINT32', n='chancount',format='DEC'},
        _types={
            [0x22] = "Bank Report cbPKTTYPE_BANKREP",
        }
    }
)

-- Filter (FILT) Information packets
local CbPktFiltInfo = CbPktConfig:new('cbPKT_FILTINFO',
    {
        PktField:new{t='UINT32', n='proc',format='DEC'},
        PktField:new{t='UINT32', n='filt',format='DEC'},
        PktField:new{t='STRING', n='label', len=cbConst.cbLEN_STR_FILT_LABEL},
        AField:new{n='hp', d='High-pass filter'},
        PktField:new{t='UINT32', n='hp.hpfreq', d='Corner freq in mHz', format='DEC'},
        PktField:new{t='UINT32', n='hp.hporder', d='Filter order', format='DEC'},
        PktField:new{t='UINT32', n='hp.hptype', d='Filter type', format='HEX'},
        FlagField:new{t='BOOLEAN', n='hp.hptype.physical', format=32, mask=0x00000001, d='Physical cbFILTTYPE_PHYSICAL', valuestring={'yes','no'}},
        FlagField:new{t='BOOLEAN', n='hp.hptype.digital', format=32, mask=0x00000002, d='Digital cbFILTTYPE_DIGITAL', valuestring={'yes','no'}},
        FlagField:new{t='BOOLEAN', n='hp.hptype.adaptive', format=32, mask=0x00000004, d='Adaptive cbFILTTYPE_ADAPTIVE', valuestring={'yes','no'}},
        FlagField:new{t='BOOLEAN', n='hp.hptype.nonlinear', format=32, mask=0x00000008, d='Nonlinear cbFILTTYPE_NONLINEAR', valuestring={'yes','no'}},
        FlagField:new{t='BOOLEAN', n='hp.hptype.butter', format=32, mask=0x00000100, d='Butterworth cbFILTTYPE_BUTTERWORTH', valuestring={'yes','no'}},
        FlagField:new{t='BOOLEAN', n='hp.hptype.cheb', format=32, mask=0x00000200, d='Chebychev cbFILTTYPE_CHEBYCHEV', valuestring={'yes','no'}},
        FlagField:new{t='BOOLEAN', n='hp.hptype.bessel', format=32, mask=0x00000400, d='Bessel cbFILTTYPE_BESSEL', valuestring={'yes','no'}},
        FlagField:new{t='BOOLEAN', n='hp.hptype.elliptical', format=32, mask=0x00000800, d='Elliptical cbFILTTYPE_ELLIPTICAL', valuestring={'yes','no'}},


        AField:new{n='lp', d='Low-pass filter'},
        PktField:new{t='UINT32', n='lp.lpfreq', d='Corner freq in mHz', format='DEC'},
        PktField:new{t='UINT32', n='lp.lporder', d='Filter order', format='DEC'},
        PktField:new{t='UINT32', n='lp.lptype', d='Filter type', format='HEX'},
        FlagField:new{t='BOOLEAN', n='lp.lptype.physical', format=32, mask=0x00000001, d='Physical cbFILTTYPE_PHYSICAL', valuestring={'yes','no'}},
        FlagField:new{t='BOOLEAN', n='lp.lptype.digital', format=32, mask=0x00000002, d='Digital cbFILTTYPE_DIGITAL', valuestring={'yes','no'}},
        FlagField:new{t='BOOLEAN', n='lp.lptype.adaptive', format=32, mask=0x00000004, d='Adaptive cbFILTTYPE_ADAPTIVE', valuestring={'yes','no'}},
        FlagField:new{t='BOOLEAN', n='lp.lptype.nonlinear', format=32, mask=0x00000008, d='Nonlinear cbFILTTYPE_NONLINEAR', valuestring={'yes','no'}},
        FlagField:new{t='BOOLEAN', n='lp.lptype.butter', format=32, mask=0x00000100, d='Butterworth cbFILTTYPE_BUTTERWORTH', valuestring={'yes','no'}},
        FlagField:new{t='BOOLEAN', n='lp.lptype.cheb', format=32, mask=0x00000200, d='Chebychev cbFILTTYPE_CHEBYCHEV', valuestring={'yes','no'}},
        FlagField:new{t='BOOLEAN', n='lp.lptype.bessel', format=32, mask=0x00000400, d='Bessel cbFILTTYPE_BESSEL', valuestring={'yes','no'}},
        FlagField:new{t='BOOLEAN', n='lp.lptype.elliptical', format=32, mask=0x00000800, d='Elliptical cbFILTTYPE_ELLIPTICAL', valuestring={'yes','no'}},


        PktField:new{t='DOUBLE', n='sos1a1'},
        PktField:new{t='DOUBLE', n='sos1a2'},
        PktField:new{t='DOUBLE', n='sos1b1'},
        PktField:new{t='DOUBLE', n='sos1b2'},
        PktField:new{t='DOUBLE', n='sos2a1'},
        PktField:new{t='DOUBLE', n='sos2a2'},
        PktField:new{t='DOUBLE', n='sos2b1'},
        PktField:new{t='DOUBLE', n='sos2b2'},
        PktField:new{t='DOUBLE', n='sos1a1'},
        _types={
            [0x23] = "Filter Report cbPKTTYPE_FILTREP",
            [0xA3] = "Filter Request cbPKTTYPE_FILTSET",
        }
    }
)

-- cbPKT_CHANRESET Factory Default settings request packet
local CbPktChanReset = CbPktConfig:new('cbPKT_CHANRESET',
    {
        AField:new{d="This packet is untested."},
        PktField:new{t='UINT32', n='chan', d="Channel"},
        PktField:new{t='UINT8', n='label', d="Reset label", valuestring={[0]='no', [1]='yes'}},
        PktField:new{t='UINT8', n='userflags', d="Reset User flags", valuestring={[0]='no', [1]='yes'}},
        PktField:new{t='UINT8', n='position', d="Reset Reserved", valuestring={[0]='no', [1]='yes'}},
        PktField:new{t='UINT8', n='scalin', d="Reset Scaling in", valuestring={[0]='no', [1]='yes'}},
        PktField:new{t='UINT8', n='scalout', d="Reset Scaling out", valuestring={[0]='no', [1]='yes'}},
        PktField:new{t='UINT8', n='doutopts', d="Reset dOut options", valuestring={[0]='no', [1]='yes'}},
        PktField:new{t='UINT8', n='dinpopts', d="Reset dIn options", valuestring={[0]='no', [1]='yes'}},
        PktField:new{t='UINT8', n='aoutopts', d="Reset aOut options", valuestring={[0]='no', [1]='yes'}},
        PktField:new{t='UINT8', n='eopchar', d="Reset endOfPacket char", valuestring={[0]='no', [1]='yes'}},
        PktField:new{t='UINT8', n='monsource', d="Reset monitor source", valuestring={[0]='no', [1]='yes'}},
        PktField:new{t='UINT8', n='outvalue', d="Reset outValue", valuestring={[0]='no', [1]='yes'}},
        PktField:new{t='UINT8', n='ainpopts', d="Reset aIn options", valuestring={[0]='no', [1]='yes'}},
        PktField:new{t='UINT8', n='lncrate', d="Reset LNC rate", valuestring={[0]='no', [1]='yes'}},
        PktField:new{t='UINT8', n='smpfilter', d="Reset filter id", valuestring={[0]='no', [1]='yes'}},
        PktField:new{t='UINT8', n='smpgroup', d="Reset sample group", valuestring={[0]='no', [1]='yes'}},
        PktField:new{t='UINT8', n='smpdispmin', d="Reset display min", valuestring={[0]='no', [1]='yes'}},
        PktField:new{t='UINT8', n='smpdispmax', d="Reset display max", valuestring={[0]='no', [1]='yes'}},
        PktField:new{t='UINT8', n='spkfilter', d="Reset spk filter", valuestring={[0]='no', [1]='yes'}},
        PktField:new{t='UINT8', n='spkdispmax', d="Reset spk disp max", valuestring={[0]='no', [1]='yes'}},
        PktField:new{t='UINT8', n='lncdispmax', d="Reset LNC disp max", valuestring={[0]='no', [1]='yes'}},
        PktField:new{t='UINT8', n='spkopts', d="Reset spk options", valuestring={[0]='no', [1]='yes'}},
        PktField:new{t='UINT8', n='spkthrlevel', d="Reset spk threshold lvl", valuestring={[0]='no', [1]='yes'}},
        PktField:new{t='UINT8', n='spkthrlimit', d="Reset spk threshold limit", valuestring={[0]='no', [1]='yes'}},
        PktField:new{t='UINT8', n='spkgroup', d="Reset spkgroup", valuestring={[0]='no', [1]='yes'}},
        PktField:new{t='UINT8', n='spkhoops', d="Reset spkhoops", valuestring={[0]='no', [1]='yes'}},
        _types={
            [0x24] = "Factory Default settings Report cbPKTTYPE_CHANRESETREP",
            [0xA4] = "Factory Default settings Request cbPKTTYPE_CHANRESET",
        }
    }
)


-- cbPKT_ADAPTFILTINFO
local CbPktAdaptFiltInfo = CbPktConfig:new('cbPKT_ADAPTFILTINFO',
    {
        PktField:new{t='UINT32', n='chan', d="Chan (Ignored)"},
        PktField:new{t='UINT32', n='nMode', valuestring=
            {
                [0]="disabled",
                [1]="filter continuous & spikes",
                [2]="filter spikes",
            }
        },

        PktField:new{t='FLOAT', n='dLearningRate'},
        PktField:new{t='UINT32', n='refChan1', d="Reference Channel 1"},
        PktField:new{t='UINT32', n='refChan2', d="Reference Channel 2"},
        _types={
            [0x25] = "Adaptive filtering Report cbPKTTYPE_ADAPTFILTREP",
            [0xA5] = "Adaptive filtering Request cbPKTTYPE_ADAPTFILTSET",
        }
    }
)

-- cbPKT_REFELECFILTINFO
local CbPktRefElecFiltInfo = CbPktConfig:new('cbPKT_REFELECFILTINFO',
    {
        PktField:new{t='UINT32', n='chan', d="Chan (Ignored)"},
        PktField:new{t='UINT32', n='nMode', valuestring=
            {
                [0]="disabled",
                [1]="filter continuous & spikes",
                [2]="filter spikes",
            }
        },
        PktField:new{t='UINT32', n='refChan', d="Reference Channel"},
        _types={
            [0x26] = "Reference Electrode filtering Report cbPKTTYPE_REFELECFILTREP",
            [0xA6] = "Reference Electrode filtering Request cbPKTTYPE_REFELECFILTSET",
        }
    }
)

-- cbPKT_LNC
local CbPktLNC = CbPktConfig:new('cbPKT_LNC',
    {
        PktField:new{t='UINT32', n='lncFreq', d="Nominal line noise frequency to be canceled  (in Hz)"},
        PktField:new{t='UINT32', n='lncRefChan', d="Reference channel for lnc synch (1-based)"},
        PktField:new{t='UINT32', n='lncGlobalMode', d="reserved"},
        _types={
            [0x28] = "Line Noise Cancellation Report cbPKTTYPE_LNCREP",
            [0xA8] = "Line Noise Cancellation Request cbPKTTYPE_LNCSET",
        }
    }
)


-- cbPKT_NM
local CbPktNM = CbPktConfig:new('cbPKT_NM',
    {
        PktField:new{t='UINT32', n='mode', valuestring=
            {
                [0]="cbNM_MODE_NONE",
                [1]="cbNM_MODE_CONFIG Ask NeuroMotive for configuration",
                [2]="cbNM_MODE_SETVIDEOSOURCE Configure video source",
                [3]="cbNM_MODE_SETTRACKABLE Configure trackable",
                [4]="cbNM_MODE_STATUS NeuroMotive status reporting (cbNM_STATUS_*)",
                [5]="cbNM_MODE_TSCOUNT Timestamp count (value is the period with 0 to disable this mode)",
                [6]="cbNM_MODE_SYNCHCLOCK Start (or stop) synchronization clock (fps*1000 specified by value, zero fps to stop capture)",
                [7]="cbNM_MODE_ASYNCHCLOCK Asynchronous clock",
            }
        },
        PktField:new{t='UINT32', n='flags', d="status of NeuroMotive"},
        PktField:new{t='UINT32', n='value'},
        PktField:new{t='UINT32', n='opt', len=cbConst.cbLEN_STR_LABEL/4},
        _types={
            [0x32] = "NeuroMotive Report cbPKTTYPE_NMREP",
            [0xB2] = "NeuroMotive Request cbPKTTYPE_NMSET",
        }
    }
)

-- cbPKT_VIDEOSYNCH
local CbPktVideosynch = CbPktConfig:new('cbPKT_VIDEOSYNCH',
    {
        PktField:new{t='UINT16', n='split', d="file split number"},
        PktField:new{t='UINT32', n='frame'},
        PktField:new{t='UINT32', n='etime', d="elapsed time"},
        PktField:new{t='UINT16', n='id', d="video source id"},
        _types={
            [0x29] = "VideoSynch Report cbPKTTYPE_VIDEOSYNCHREP",
            [0xA9] = "VideoSynch Request cbPKTTYPE_VIDEOSYNCHSET",
        }
    }
)

-- cbPKT_VIDEOTRACK
local CbPktVideoTrack = CbPktConfig:new('cbPKT_VIDEOTRACK',
    {
        PktField:new{t='UINT16', n='parentID'},
        PktField:new{t='UINT16', n='nodeID'},
        PktField:new{t='UINT16', n='nodeCount'},
        PktField:new{t='UINT16', n='pointCount'},
        _types={
            [0x5F] = "VideoTrack Report cbPKTTYPE_VIDEOTRACKREP",
            [0xDF] = "VideoTrack Request cbPKTTYPE_VIDEOTRACKSET",
        }
    }
)

-- cbPKT_NPLAY
local CbPktNPlay = CbPktConfig:new('cbPKT_NPLAY',
    {
        PktField:new{t='UINT64', n='ftime', d='ftime'},
        PktField:new{t='UINT64', n='stime', d='stime'},
        PktField:new{t='UINT64', n='etime', d='etime'},
        PktField:new{t='UINT64', n='val', d='val'},
        PktField:new{t='UINT16', n='mode', valuestring=
            {
                [0]="cbNPLAY_MODE_NONE",
                [1]="cbNPLAY_MODE_PAUSE pause if val is non-zero, un-pause otherwise",
                [2]="cbNPLAY_MODE_SEEK seek to time val",
                [3]="cbNPLAY_MODE_CONFIG request full config",
                [4]="cbNPLAY_MODE_OPEN open new file in val for playback",
                [5]="cbNPLAY_MODE_PATH use the directory path in fname",
                [6]="cbNPLAY_MODE_CONFIGMAIN request main config packet",
                [7]="cbNPLAY_MODE_STEP run val procTime steps and pause, then send cbNPLAY_FLAG_STEPPED",
                [8]="cbNPLAY_MODE_SINGLE single mode if val is non-zero, wrap otherwise",
                [9]="cbNPLAY_MODE_RESET reset nPlay",
                [10]="cbNPLAY_MODE_NEVRESORT resort NEV if val is non-zero, do not if otherwise",
                [11]="cbNPLAY_MODE_AUDIO_CMD perform audio command in val (cbAUDIO_CMD_*), with option opt",
            }
        },
        PktField:new{t='UINT16', n='flag', valuestring=
            {
                [0]="cbNPLAY_FLAG_NONE no flag",
                [1]="cbNPLAY_FLAG_CONF config packet (val is fname file index)",
                [3]="cbNPLAY_FLAG_MAIN main config packet (val is file version)",
                [2]="cbNPLAY_FLAG_DONE step command done",
            }
        },
        PktField:new{t='FLOAT', n='speed'},
        PktField:new{t='STRING', n='fname', len=256},
        _types={
            [0x5C] = "NPlay Report cbPKTTYPE_NPLAYREP",
            [0xDC] = "NPlay Request cbPKTTYPE_NPLAYSET",
        }
    }
)

-- cbPKT_AOUT_WAVEFORM Analog output packets
local CbPktAoutWaveform = CbPktConfig:new('cbPKT_AOUT_WAVEFORM',
    {
        PktField:new{t='UINT16', n='chan', d="Which analog output/audio output channel (1-based)"},

        PktField:new{t='UINT16', n='mode', valuestring=
            {
                [0]="cbWAVEFORM_MODE_NONE Disabled",
                [1]="cbWAVEFORM_MODE_PARAMETERS repeated sequence",
                [2]="cbWAVEFORM_MODE_SINE sinusoid",
            }
        },
        PktField:new{t='UINT32', n='repeats'},
        PktField:new{t='UINT8', n='trig', valuestring=
            {
                [0]="cbWAVEFORM_TRIGGER_NONE instant software trigger",
                [1]="cbWAVEFORM_TRIGGER_DINPREG digital input rising edge trigger",
                [2]="cbWAVEFORM_TRIGGER_DINPFEG digital input falling edge trigger",
                [3]="cbWAVEFORM_TRIGGER_SPIKEUNIT spike unit",
                [4]="cbWAVEFORM_TRIGGER_COMMENTCOLOR comment RGBA color (A being big byte)",
                [5]="cbWAVEFORM_TRIGGER_SOFTRESET soft-reset trigger",
                [6]="cbWAVEFORM_TRIGGER_EXTENSION extension trigger",
            }
        },
        PktField:new{t='UINT8', n='trigInst'},
        PktField:new{t='UINT16', n='trigChan'},
        PktField:new{t='UINT16', n='trigValue'},
        PktField:new{t='UINT8', n='active'},

        AField:new{n='waveform'},
        PktField:new{t='INT16', n='waveform.offset'},
        PktField:new{t='UINT16', n='waveform.seq'},
        PktField:new{t='UINT16', n='waveform.seqTotal'},
        PktField:new{t='UINT16', n='waveform.phases'},
        PktField:new{t='UINT16', n='waveform.duration', lf='waveform.phases'},
        PktField:new{t='INT16', n='waveform.amplitude', lf='waveform.phases'},
        _types={
            [0x33] = "Analog Out Waveform Report cbPKTTYPE_WAVEFORMREP",
            [0xB3] = "Analog Out Waveform Request cbPKTTYPE_WAVEFORMSET",
        }
    }
)


-- cbPKT_SS_DETECT
local CbPktSSDetect = CbPktConfig:new('cbPKT_SS_DETECT',
    {
        PktField:new{t='FLOAT', n='fThreshold'},
        PktField:new{t='FLOAT', n='fMultiplier'},
        _types={
            [0x52] = "SS Detect Report cbPKTTYPE_SS_DETECTREP",
            [0xD2] = "SS Detect Request cbPKTTYPE_SS_DETECTSET",
        }
    }
)

-- cbPKT_SS_ARTIF_REJECT
local CbPktSSArtifReject = CbPktConfig:new('cbPKT_SS_ARTIF_REJECT',
    {
        PktField:new{t='UINT32', n='nMaxSimulChans', d="How many channels can fire exactly at the same time?"},
        PktField:new{t='UINT32', n='nRefractoryCount', d="For how many samples (30 kHz) is a neuron refractory, so can't re-trigger"},
        _types={
            [0x53] = "Artifact Rejection Report cbPKTTYPE_SS_ARTIF_REJECTREP",
            [0xD3] = "Artifact Rejection Request cbPKTTYPE_SS_ARTIF_REJECTSET",
        }
    }
)

-- DOut set packets
local CbPktDOut = CbPktConfig:new('cbPKT_SET_DOUT',
    {
        PktField:new{t='INT16', n='chan', format='DEC'},
        PktField:new{t='INT16', n='value'},
        _types={
            [0x5D] = "Set Dout Report cbPKTTYPE_SET_DOUTREP",
            [0xDD] = "Set Dout Request cbPKTTYPE_SET_DOUTSET",
        }
    }
)

-- Preview streams
-- Configuration
local CbPktPrevStreamCfg = CbPktPrevStreamBase:new('prevStreamCfg',
    {
        _types={
            [0x03] = "Cfg Prev Stream Response cbPKTTYPE_PREVREP",
            [0x81] = "Cfg Prev Stream Request cbPKTTYPE_PREVSETLNC",
            [0x82] = "Cfg Prev Stream Request cbPKTTYPE_PREVSETSTREAM",
            [0x83] = "Cfg Prev Stream Request cbPKTTYPE_PREVSET",
        }
    }
)

--  Line Noise Cancellation waveform preview
local CbPktLNCPrev = CbPktPrevStreamBase:new('cbPKT_LNCPREV',
    {
        PktField:new{t='UINT32', n='freq', format='DEC', d='Estimated line noise frequency in mHz'},
        PktField:new{t='INT16', n='wave', len=300},
        _types={
            [0x01] = "LNC Prev Stream cbPKTTYPE_PREVREPLNC",
        }
    }
)

-- Comment Packets
local CbPktComment = CbPktConfig:new('cbPKT_COMMENT',
    {
        PktField:new{t='UINT8', n='type', format='HEX'},
        PktField:new{t='UINT8', n='flags', d='Comment flags', format='HEX', valuestring={
            [0x00]="RGBA cbCOMMENT_FLAG_RGBA",
            [0x01]="RGBA cbCOMMENT_FLAG_TIMESTAMP",
        }},
        PktField:new{t='UINT8', n='reserved', format='HEX'},
        PktField:new{t='UINT8', n='reserved', format='HEX'},
        PktField:new{t='UINT32', n='data', format='HEX'},
        PktField:new{t='STRING', n='comment', len=128},
        _types={
            [0x31] = "Comment response cbPKTTYPE_COMMENTREP",
            [0xB1] = "Comment request cbPKTTYPE_COMMENTSET",
        }
    }
)

-- LOG Packets
local CbPktLog = CbPktConfig:new('cbPKT_LOG',
    {
        PktField:new{t='UINT16', n='mode', d='Log Mode', format='HEX', valuestring={
            [0x00]="Normal log cbLOG_MODE_NONE",
            [0x01]="Critical log cbLOG_MODE_CRITICAL",
            [0x02]="RPC log cbLOG_MODE_RPC",
            [0x03]="RPC log cbLOG_MODE_PLUGINFO",
            [0x04]="RPC log cbLOG_MODE_RPC_RES",
            [0x05]="RPC log cbLOG_MODE_PLUGINERR",
            [0x06]="RPC log cbLOG_MODE_RPC_END",
            [0x07]="RPC log cbLOG_MODE_RPC_KILL",
            [0x08]="RPC log cbLOG_MODE_RPC_INPUT",
            [0x09]="RPC log cbLOG_MODE_UPLOAD_RES",
            [0x0A]="RPC log cbLOG_MODE_ENDPLUGIN",
            [0x0B]="RPC log cbLOG_MODE_REBOOT",
        }},
        PktField:new{t='STRING', n='name', len=16},
        PktField:new{t='STRING', n='desc', len=128},
        _types={
            [0x63] = "LOG response cbPKTTYPE_LOGREP",
            [0xE3] = "LOG request cbPKTTYPE_LOGSET",
        }
    }
)


-- Preview Stream
local CbPktStreamPrev = CbPktPrevStreamBase:new('cbPKT_STREAMPREV',
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
        _types= {
            [0x02] = "Prev Stream cbPKTTYPE_PREVREPSTREAM",
        }
    }
)

-- Data packets (chid < 0x8000)
-- Sample Group packets
local CbPktGroup = CbPkt:new('cbPKT_GROUP',
    {
        PktField:new{t='INT16', n='data', lf='dlen', lfactor=2},
    }
)
CbPktGroup.fields['type'].d='Sample Group ID (1-127)'
CbPktGroup.fields['type'].format='DEC'

function CbPktGroup:makeInfoString()
    return self.name .. "(" .. self.dfields['type']()() .. ")"
end

-- Spike packets
local CbPktNev = CbPkt:new('nevPKT_SPK',
    {
        PktField:new{t='INT16', n='data', lf='dlen', lfactor=2},
    }
)
CbPktNev.fields['type'].d='Packet Type'
CbPktNev.fields['type'].format='DEC'

-- DigIn packets
local CbPktNevDigIn = CbPkt:new('nevPKT_DIGIN',
    {
        PktField:new{t='UINT32', n='data', lf='dlen', format='HEX_DEC'},
    }
)
CbPktNevDigIn.fields['type'].d='Packet Type'
CbPktNevDigIn.fields['type'].format='DEC'

-- Packet definitions end here.


-- Now we define something that will make our protocol

local ProtoMaker = klass:new{
    name='Cerebus',
    desc="Cerebus NSP Communication",
    colname="Cerebus",
    ports={51001, 51002, 51003}
}
function ProtoMaker:new(o)
    o = o or {}
    local newobj = klass.new(self)
    for k,v in pairs(o) do newobj[k] = v end
    newobj.proto = Proto(newobj.name, newobj.desc)
    newobj.pfields = newobj.proto.fields
    newobj.fByPkt = {}
    return newobj
end
function ProtoMaker:register()
--    info("register proto ...")

    for _,p in pairs(CbPkt.pkttypes) do
        self:makeFieldsForPacket(p)
    end

    local fe_interface_id_f = Field.new("frame.interface_id")

    function self.proto.dissector(buffer, pinfo, tree)
        pinfo.cols.protocol = self.colname
        local buflen = buffer:len()
        local offset = 0
        local header_len = 16
        local buf_remain = buffer():tvb()
        local i = 0
        while buflen >= header_len do
            local chid = buf_remain(8,2):le_uint()
            local ptype = buf_remain(10,1):uint()
            local packet = CbPkt:match(chid, ptype)
            -- get current
            local packet_len = buf_remain(11,2):le_uint() * 4 + header_len


            local subtree = tree:add(self.proto, buf_remain(0, packet_len), "Cerebus Protocol Data (" .. packet.name .. ")(" .. packet_len ..")" )

            self:addSubtreeForPkt(buf_remain(0, packet_len):tvb(), subtree, packet)
            buflen = buflen - packet_len
            buf_remain = buf_remain(packet_len):tvb()
            if i == 0 then
                pinfo.cols.info = packet:makeInfoString()
            end

            i = i + 1
        end
        if i > 1 then
            pinfo.cols.info:append(" (+ " .. (i-1) .. " other" .. (i>2 and 's' or '') .. ")")
        end

        local f_interface_id = fe_interface_id_f()
        pinfo.cols.info:prepend("NSP:" .. tostring(f_interface_id) .. " ")

    end
    local udp_table = DissectorTable.get("udp.port")
    -- register our protocol to handle udp ports
    for _, p in ipairs(self.ports) do
        udp_table:add(p, self.proto)
    end
end
function ProtoMaker:makeFieldsForPacket(pkt)
    local n = self.name .. "." .. pkt.name .. "."
    local fn = pkt.name .. "_"
    self.fByPkt[pkt] = {}
    for i, f in ipairs(pkt.fields) do
        local thisfn = fn .. f.n
        local thisn = n .. f.n
        local pf

        if f.ftype~='afield' and f.ftype~='flagfield' then
            pf = ProtoField.new(f.d and f.d or f.n, thisn, ftypes[f.t], f.valuestring, base[f.format], f.mask, f.d)
        elseif f.ftype=='flagfield' then
            pf = ProtoField.new(f.d and f.d or f.n, thisn, ftypes[f.t], f.valuestring, f.format, f.mask, f.d)
        end
        if pf~=nil then
            self.pfields[thisfn] = pf
            self.fByPkt[pkt][f.n] = pf

            local df = Field.new(thisn)
            table.insert(pkt.dfields, df)
            pkt.dfields[f.n] = df
        end
    end
end

function ProtoMaker:addSubtreeForPkt(buffer, tree, pkt)
    local tree_stack = Stack:Create({t=tree, p="", br=buffer()})

    for i, bPos, width, pf, mult in pkt:iterate(buffer:len()) do
        local current_parent_tree = nil
        local current_parent_br = nil
        repeat
            local last_tree = tree_stack:last()
            local i,j = string.find(pf.n, last_tree.p)
            if i==1 and j > 0 and string.sub(pf.n, j+1, j+1)=='.' then
                current_parent_tree = last_tree.t
                current_parent_br = last_tree.br
                -- tree_stack:push(last_tree)
            elseif i==1 and j==0 then
                current_parent_tree = last_tree.t
                current_parent_br = last_tree.br
            else
                tree_stack:pop()
            end
        until current_parent_tree ~= nil
        local subtree
        local tvb_rng_wh
        if pf.ftype == 'afield' then
            subtree = current_parent_tree:add(pf.d ~= nil and pf.d or pf.n )
        elseif pf.ftype == 'flagfield' then
            subtree = current_parent_tree:add_le(self.fByPkt[pkt][pf.n], current_parent_br)
        else
            if mult > 0 then
                tvb_rng_wh = buffer(bPos, width * mult)
                local brng = buffer(bPos, width)
                local this_rangeGetter = pf:rangeGetter()
                if this_rangeGetter ~= nil then
                    subtree = current_parent_tree:add_le(self.fByPkt[pkt][pf.n], tvb_rng_wh, brng[pf:rangeGetter()](brng) )
                else
                    subtree = current_parent_tree:add_le(self.fByPkt[pkt][pf.n], tvb_rng_wh)
                end
                if mult > 1 then
                    local n = mult - 1
                    subtree:append_text(" and "..n.." more item"..(n>1 and "s" or ""))
                    for i=0,n do
                        brng = buffer(bPos + width * i, width)
                        subtree:add( brng, 'item '..i..': ' .. brng[pf:rangeGetter()](brng))
                    end
                end
            end
        end
        tree_stack:push({t=subtree, p=pf.n, f=pf, br=tvb_rng_wh})

    end
end

-- instantiate Protocol maker
local pm = ProtoMaker:new()
pm:register()
