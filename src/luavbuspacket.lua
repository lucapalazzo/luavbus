--------------------------------------------------------------------------------
-- LUA VBus packet .
-- A module representint a vbus packet 
--
-- @module luavbuspacket
-- @return #luavbuspacket
 
---@type luavbuspacket

local luavbuspacket = {}
luavbuspacket_mt = { __index = luavbuspacket }

luavbuspacket.srcAddress = 0 -- source address (2 byte)
luavbuspacket.dstAddress = 0 -- destination address (2 byte)
luavbuspacket.protoVersion = 1 -- protocol version 0x10 o 0x20 or 0x30 (1 byte)
--- packet version
luavbuspacket.version = 0 -- version (1 byte)
luavbuspacket.command = 0 -- command (2 bytes)
luavbuspacket.payloads = 0 -- number of payloads (2 bytes)
luavbuspacket.payloadsData = nil -- 4-byte payloads
luavbuspacket.dataPointID = nil -- ID of the data point (2 bytes)
luavbuspacket.dataPointValue = nil -- value of data point ( 4 bytes)
luavbuspacket.checksum = 0 -- CRC (1 bytes)
luavbuspacket.profile = nil -- vbus profile
luavbuspacket.profileData = nil -- vbus profile data



luavbuspacket.mt = {} -- metatable

--- Creates a new instance of luavbuspacket
-- @author Luca Palazzo
-- @return instance of luavbuspacket
-- 
function luavbuspacket.new ( o )
  luavbuspacket.log ( DEBUG3, string.format ( "luavbuspacket.new( %s )", o ) )
  local _vp = o or {}
  luavbuspacket.log ( DEBUG4, string.format ( "luavbuspacket.new(): %s", _vp ) )
  
  setmetatable(_vp, luavbuspacket_mt )
  luavbuspacket_mt.__tostring = luavbuspacket.tostring
  return _vp
end

--- Stringify luavbuspacket object. Use in __tostring metatable field too
-- @author Luca Palazzo
-- @param packet the instance of luavbuspacket to stringify
-- @return string-fied version of luavbuspacket
function luavbuspacket.tostring( packet )
  luavbuspacket.log ( DEBUG3, "luavbuspacket.tostring( packet )" )
--  if ( packet == nil or packet.srcAddress == nil ) then
--    return "nil packet"
--  end
  vbus_packet_string = string.format( "VBus frame source address 0x%04x destination address  0x%04x version 0x%02x command 0x%02x checksum 0x%04x payloads %d", packet.srcAddress, packet.dstAddress, packet.version, packet.command, packet.checksum, packet.payloads ) 
  luavbuspacket.log ( DEBUG3,  vbus_packet_string )
  return vbus_packet_string
end

function luavbuspacket.profileprint( packet )
  luavbuspacket.log ( DEBUG3, "luavbuspacket.profilestring( packet )" )
  vbus_packet_string = ""
  if ( packet == nil ) then
    return "no packet"
  end
  
  if ( packet.profile == nil ) then
    return "no profile"
  end
  
  if ( packet.profile.objects == nil ) then
    return "no objects"
  end
  
  for k, v in pairs( packet.profile.objects ) do
    local offset = tonumber(v[1])
    local length = tonumber(v[2])
    local unknown = tonumber(v[3])
    local name = v[4]
    local factor = tonumber(v[5])
    local unit = v[6]
    if (unit==nil) then
      unit = ""
    end
    luavbuspacket.log( DEBUG4, string.format ("Offset %d length %d", offset, length ) )
    
    local value = 0
    packet_length = string.len(packet.payloadsData)
    -- PacketDump(data)
    for index = 1, length, 1 do
      if ( offset+index > packet_length ) then
        luavbuspacket.log ( DEBUG3, string.format ("Buffer overrun (length %d)", packet_length ) )
        break
      end
      luavbuspacket.log ( DEBUG4, string.format ("Getting byte %d at offset %d with value 0x%02x", index, offset, packet.payloadsData:byte(offset+index) ) )
      -- print ("Adding "..data:byte(offset+index+1)*(256^index))
      value = value + packet.payloadsData:byte(offset+index)*(256^(index-1))
      -- print ( "Value: " .. value .. " index " .. index )
    end
    
    
    luavbuspacket.log ( DEBUG2, string.format ("luavbus:packetParseV1(): name %s Value %02.2f %s", name, value*factor, unit ) )
    vbus_packet_string = vbus_packet_string .. string.format ("%s: %02.2f %s ", name, value*factor, unit )

  end
--  vbus_packet_string = string.format( "VBus frame source address 0x%04x destination address  0x%04x version 0x%02x command 0x%02x checksum 0x%04x", packet.srcAddress, packet.dstAddress, packet.version, packet.command, packet.checksum ) 
  luavbuspacket.log ( DEBUG4,  vbus_packet_string )
  return vbus_packet_string
end

function luavbuspacket.getProfileData( self )
  luavbuspacket.log ( DEBUG3, "luavbuspacket.getProfileData()" )
  
  if ( self.profile == nil ) then
    luavbuspacket.log ( WARN, "Packet ha no profile" )
    return nil
  end
  
  self.profileData = {}

  for k, object in pairs( self.profile.objects ) do    
    local offset = tonumber(object[1])
    local length = tonumber(object[2])
    local unknown = tonumber(object[3])
    local name = object[4]
    local factor = tonumber(object[5])
    local unit = object[6]
    local value = 0
    
    if (unit==nil) then
      unit = ""
    end
    luavbuspacket.log( DEBUG4, string.format ("Offset %d length %d", offset, length ) )
    
    packet_length = string.len(self.payloadsData)
    for index = 1, length, 1 do
      if ( offset+index > packet_length ) then
        luavbuspacket.log ( WARN, string.format ("Buffer overrun (length %d)", packet_length ) )
        break
      end
      luavbuspacket.log ( DEBUG2, string.format ("Getting byte %d at offset %d with value 0x%02x", index, offset, self.payloadsData:byte(offset+index) ) )
      -- print ("Adding "..data:byte(offset+index+1)*(256^index))
      value = value + self.payloadsData:byte(offset+index)*(256^(index-1))
      -- print ( "Value: " .. value .. " index " .. index )
    end
    data = {}
    data.name = name
    data.factor = factor
    data.unit = unit
    data.value = value*factor
    table.insert(self.profileData, data)
    luavbuspacket.log ( DEBUG2, string.format ("luavbuspacket.getProfileData(): name %s value %.02f",data.name, data.value ) )
      
  end
end

function luavbuspacket.log ( level, ... )
  local prefix = ""
  local log_string = ""
  if ( log_level ~= nil and level ~= nil and level <= log_level ) then
    if ( level == ERR ) then
      log_string = "ERROR"
    elseif ( level == WARN ) then
      log_string = "WARN"
    elseif ( level == INFO ) then
      log_string = "INFO"  
    elseif ( level == DEBUG1 ) then
      log_string = "DEBUG1"
    elseif ( level == DEBUG2 ) then
      log_string = "DEBUG2"
    elseif ( level == DEBUG3 ) then
      log_string = "DEBUG3"
    elseif ( level == DEBUG4 ) then
      log_string = "DEBUG4"
    elseif ( level == DEBUG5 ) then
      log_string = "DEBUG5"
    else
      log_string = "UNKNOWN"
    end
    print ( log_string .. ": " .. ... )
  end
end

return luavbuspacket