local log = debug
_G.debug = require("debug")
klass = {}
function klass:new (o)
  o = o or {}
  setmetatable(o, self)
  self.__index = self
  return o
end

PktField = klass:new{
        t='uint8',
        n='name',
        lf=nil,
        len=nil,
        d='desc',
        format='HEX'
    -- new=function(self, type, name, lenfield)
    --     return klass.new(self, {t=type, n=name, lenfield=lenfield})
    -- end
}

CbPkt = klass:new{
    name='HEADER',
    fields={
        PktField:new{t='uint32', n='time'},
        PktField:new{t='uint16', n='chid'},
        PktField:new{t='uint8', n='type'},
        PktField:new{t='uint8', n='dlen'}
    }
}
function CbPkt:new(name, addfields)
    local newobj = klass.new(self)
    newobj.name = name
    addfields = addfields or {}
    for _, f in pairs(addfields) do
        table.insert(newobj.fields, f)
    end
    for i, f in ipairs(newobj.fields) do
        print(f.n)
        print(i)
        newobj.fields[f.n] = f
    end
    return newobj
end
function CbPkt:match(chid, type)
    return false
end

CbPktGeneric = CbPkt:new('GENERIC',
    {
        PktField:new{t='uint32', n='data', lf='dlen'},
    }
)
function CbPktGeneric:match(chid, type)
    return true
end


CbPktStreamPrev = CbPkt:new('STREAMPREV',
    {
        PktField:new{t='int16', n='rawmin'},
        PktField:new{t='int16', n='rawmax'},
        PktField:new{t='int16', n='smpmin'},
        PktField:new{t='int16', n='smpmax'},
        PktField:new{t='int16', n='spkmin'},
        PktField:new{t='int16', n='spkmax'},
        PktField:new{t='uint32', n='spkmos'},
        PktField:new{t='uint32', n='eventflag'},
        PktField:new{t='int16', n='envmin'},
        PktField:new{t='int16', n='envmax'},
        PktField:new{t='int32', n='spkthrlevel'},
        PktField:new{t='uint32', n='nWaveNum'},
        PktField:new{t='uint32', n='nSampleRows'},
        PktField:new{t='uint32', n='nFlags'},
    }
)
function CbPktStreamPrev:match(chid, type)
    local p_types = {
        [0x81] = true,
        [0x82] = true,
        [0x83] = true,
        [0x03] = true,
        [0x01] = true,
        [0x02] = true,
    }
    return bit32.band(chid, 0x8000) ~= 0 and p_types[type] ~= nil
end


function makeFieldsForPacket(fields, pkt)
    local n = "Cerebus." .. pkt.name .. "."
    local fn = pkt.name .. "_"
    for i, f in ipairs(pkt.fields) do
        local thisfn = fn .. f.n
        local thisn = n .. f.n
        fields[thisfn] = ProtoField[f.t](thisn, f.n, base[f.format])
    end
end


ProtoMaker = klass:new{
    name='Cerebus',
    desc="Cerebus NSP Communication",
    colname="Cerebus",
    port=51001
}
function ProtoMaker:new(o)
    o = o or {}
    local newobj = klass.new(self)
    for k,v in pairs(o) do newobj[k] = v end
    newobj.proto = Proto(newobj.name, newobj.desc)
    newobj.pfields = newobj.proto.fields
    return newobj
end
function ProtoMaker:register()
    function self.proto.dissector(buffer, pinfo, tree)
        pinfo.cols.protocol = self.colname
    end
    local udp_table = DissectorTable.get("udp.port")
    -- register our protocol to handle udp port (default 51001)
    udp_table:add(self.port, self.proto)
end
function ProtoMaker:makeFieldsForPacket(pkt)
    local n = self.name .. "." .. pkt.name .. "."
    local fn = pkt.name .. "_"
    for i, f in ipairs(pkt.fields) do
        local thisfn = fn .. f.n
        local thisn = n .. f.n
        print(thisn)
        log(thisn)
        self.pfields[thisfn] = ProtoField[f.t](thisn, f.n, base[f.format])
    end
end


local pm = ProtoMaker:new()
pm:makeFieldsForPacket(CbPktStreamPrev)
pm:makeFieldsForPacket(CbPktGeneric)
pm:register()
