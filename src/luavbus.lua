--------------------------------------------------------------------------------
-- LUA VBus.
-- A module to handle data exchange and retrive witn VBus compatible devices (most Resol) 
--
-- @module luavbus
-- @return #luavbus
 
---@type luavbus
local luavbus = {}

socket = require ("socket")

for _, searcher in ipairs(package.searchers or package.loaders) do
  name = "cjson"
  local loader = searcher(name)
  if type(loader) == 'function' then
    package.preload[name] = loader
    cjson  = require (name)
    break
  end
  name = "json"
  local loader = searcher(name)
  if type(loader) == 'function' then
    package.preload[name] = loader
    cjson  = require (name)
    break
  end     
end

for _, searcher in ipairs(package.searchers or package.loaders) do
  name = "vbusprofiles"
  local loader = searcher(name)
  if type(loader) == 'function' then
    package.preload[name] = loader
    vbusprofiles  = require (name)
    break
  end
  name = "user.vbusprofiles"
  local loader = searcher(name)
  if type(loader) == 'function' then
    package.preload[name] = loader
    vbusprofiles  = require (name)
    break
  end     
end

for _, searcher in ipairs(package.searchers or package.loaders) do
  name = "luavbuspacket"
  local loader = searcher(name)
  if type(loader) == 'function' then
    package.preload[name] = loader
    luavbuspacket  = require (name)
    break
  end
  name = "user.luavbuspacket"
  local loader = searcher(name)
  if type(loader) == 'function' then
    package.preload[name] = loader
    luavbuspacket  = require (name)
    break
  end     
end

local SERIAL, TCPIP = 0, 1

---
-- Type of connection used with VBus device (TCPIP or SERIAL)
--
-- @field [parent=#luavbus] #string connection_type 
luavbus.connection_type = TCPIP
---
-- Device to connect, IP address in case of TCPIP or serial device in case of SERIAL
--
-- @field [parent=#luavbus] #string device 
luavbus.device = nil
luavbus.remote_host = nil
luavbus.remote_port = nil
luavbus.buffer_size = 256
luavbus.buffer = nil
luavbus.password = nil
luavbus.datacount = 0
luavbus.socket = nil
luavbus.buffer = ""
luavbus.profiles = {}

--- Creates a new instance of luavbus
-- @author Luca Palazzo
-- @return instance of luavbuspacket
-- 
function luavbus.new ( vbus_device, vbus_connection_type, vbus_password )
  _v = {}
  if ( vbus_device == nil ) then
    luavbus.log ( DEBUG1, "No device specified" )
    return nil
  end
  
  if ( vbus_connection_type ~= nil ) then
    luavbus.log ( DEBUG1, "Setting connectiont type to " .. vbus_connection_type )
    self.connection_type = vbus_connection_type
  end
  
  if ( vbus_password ~= nil ) then
    luavbus.log ( DEBUG1, "Setting password to " .. vbus_password )
    self.password = vbus_password
  end
  
  self.buffer = ""
  setmetatable(_v, self)
  _v.__index = _v
  return _v
end

--- Connect to the device
-- @author Luca Palazzo
-- @return the socket or nil on failure
-- 
function luavbus:connect ()
  luavbus.log ( 5, "luavbus:connect(): starting connection to the device" )
  if ( self.connection_type == SERIAL ) then
    luavbus.log ( DEBUG1, "Serial connection not yet implemented")
    return nil
  else
    luavbus.log ( DEBUG1, "Using  TCPIP connection")
  end

  if (self.remote_host == nil or self.remote_port == nil ) then
    luavbus.log ( ERR, "TCPIP connection parameters missing")
    return nil
  end

  self.socket = socket.connect(self.remote_host,self.remote_port)
  self.socket:settimeout(0.5)
  self.socket:setoption("keepalive",true)
  if ( self.socket == nil ) then
    luavbus.log ( ERR, "Error opening socket" )
    return nil
  end
--  debug ( 5, string.format ( "Socket: %s", tostring ( self.socket )))
  luavbus.log ( DEBUG3, "luavbus:connect(): waiting for +HELLO" )
  incoming = self:getResponse()
  incoming = incoming:sub(1, -2)
  luavbus.log ( DEBUG3, string.format ( "luavbus:connect(): received %s ", incoming ) )
  if ( incoming ~= "+HELLO" ) then
    luavbus.log ( ERR, string.format ("Error in incoming string: %s|", incoming) )
  end 
    
  luavbus.log ( DEBUG3, "luavbus:connect(): sending PASS" )
  self:sendCommand( "PASS ".. self.password )
  incoming = self:getResponse()
  if ( incoming == nil ) then
    luavbus.log ( WARN, "luavbus:connect(): error getting answer from device to command PASS" )  
    return nil
  end
  incoming = incoming:sub(1, -2)

  luavbus.log ( DEBUG3, "luavbus:connect(): waiting for +OK" )
  if ( incoming ~= "+OK: Password accepted" ) then
    luavbus.log ( 1, "Error in incoming string: ".. incoming)
  end
  luavbus.log ( DEBUG3, string.format ( "luavbus:connect(): received %s ", incoming ) )
  
  self:sendCommand("DATA")
  
  return self.socket
  
end

--- Get the response from device
-- @author Luca Palazzo
-- @return a string containing thre response or nil
--
function luavbus:getResponse ()
  luavbus.log ( DEBUG3, string.format ( "luavbus:getResponse()" ) )   
  retries = 0
  repeat
    incoming, error, partial = self.socket:receive (512);
    if ( incoming == nil) then
        luavbus.log ( DEBUG1, string.format ( "luavbus:getResponse(): incoming nil (%s)", tostring(incoming) ) )   
    end
    if ( error == 'timeout' and partial ) then
      luavbus.log ( DEBUG3, "luavbus:getResponse(): partial string." )
      incoming = partial
      break
    end
    retries = retries + 1
    if ( retries > 3 ) then
      break
    end
  until incoming ~= nil
  return incoming
end

--- Sends data to the device
-- @author Luca Palazzo
-- @return the socket or nil on failure
--
function luavbus:sendCommand ( command )
  res = self.socket:send( command )
  return res    
end

--- Waits for data from device until timeout. In case of filter it search for only the filter
-- @author Luca Palazzo
-- @param filter a table containing the filters in form of "filter = { srcAddress = 0x7e11, dstAddress = 0x0010 }", nil in case of no filter
-- @param timeout the time to wait to return the packtes received and mateching di filter
-- @return a table containing received packets
--
function luavbus:waitData ( filter, timeout )
  local i = 0
  local datacount = 0
  
  if ( timeout == nil ) then
  luavbus.log ( DEBUG2, string.format ( "luavbus:waitData(): using default timeout of 5s" ) )
    timeout = 5
  end
  self:readDevicesProfiles()
  local found = false 
  local tries = 0
  local packets = {}
--  while 1 do
  start_time = os.time()
  luavbus.log ( DEBUG2, string.format ( "luavbus:waitData(): start_time %d", start_time ) )
  
  repeat
  --  posix.sleep(1)
    if ( ( os.time() - start_time ) > timeout ) then
      luavbus.log ( DEBUG2, string.format ( "luavbus:waitData(): timed out" ) )
      return packets 
    end
    
    incoming = self:getResponse()
    -- client:receive (buffersize);
    if ( incoming == nil ) then
      luavbus.log ( DEBUG2, string.format ( "luavbus:waitData(): nil incoming data, socket %s", self.socket ) )
      socket.select(nil, nil, 1)
      tries = tries + 1
      if ( tries > 3) then
        luavbus.log ( DEBUG2, "luavbus:waitData(): retries exhausted exiting")
        return packets
      end
    else
    
    
    tries = 0
    i = i + 1
    if datacount > 1 then
      break
    end
        
    luavbus.log ( DEBUG1, string.format ( "Incoming dump: %s ", self.packetdump(incoming) ) )
    vbus_frames = self:packetExtract(incoming)
    if ( vbus_frames ~= nil and type(vbus_frames) == "table" ) then
      luavbus.log ( DEBUG2, string.format ( "luavbus:waitData(): multi packets %d", #vbus_frames ) )
      for k,vbus_frame in pairs(vbus_frames) do
        luavbus.log ( DEBUG2, string.format ( "luavbus:waitData(): vbus_frame dump %s", self:packetdump(vbus_frame) ) )
        vbus_packet = self:packetParse(vbus_frame)
        luavbus.log ( DEBUG2, string.format ( "luavbus:waitData(): vbus_packet  %s", vbus_packet ) )
        
      end

      local found = 0
      if ( vbus_packet ~= nil) then 
        for k,v in pairs(self.profiles) do
          luavbus.log ( DEBUG2, string.format( "Comparing with profile ID %s Name %s ", v.id, v.name) )
          if vbus_packet.srcAddress == tonumber(v.id) and vbus_packet.dstAddress == 0x10 then
            luavbus.log ( DEBUG2, string.format( "Found ID %s Name %s ", v.id, v.name) )
            definition = v
            found = true
            vbus_packet.profile = v
            vbus_packet:getProfileData()
            break
          end
        end
 
        if ( filter == nil or type(filter) ~= "table") then
          luavbus.log ( DEBUG2, string.format ( "luavbus:waitData(): returning any VBus packets" ) )
          luavbus.log ( DEBUG2, string.format ( "Packet source 0x%04x destination 0x%04x command 0x%04x payloads %d checksum 0x%02x", vbus_packet.srcAddress, vbus_packet.dstAddress, vbus_packet.command, vbus_packet.payloads, vbus_packet.checksum ) )
          luavbus.log ( DEBUG2, tostring(vbus_packet) )
          table.insert(packets, vbus_packet)
          
  --        debug ( 5, string.format ( "Packet source %s destination %s command %s payloads %s checksum %s", tostring(vbus_packet.srcAddress), tostring(vbus_packet.dstAddress), tostring(vbus_packet.command), tostring(vbus_packet.payloads), tostring(vbus_packet.checksum) ) )
          
        else
          local filtercount = 0
          local filtermask = 0
          local mask = 0
          for _ in pairs(filter) do filtercount = filtercount + 1 end
          luavbus.log ( 5, string.format ( "luavbus:waitData(): returning packets filtered. Number of filters %d", filtercount ) )
          if ( filter.srcAddress ~= nil ) then
            filtermask = bit32.bor(filtermask, 1)
            if ( vbus_packet.srcAddress == filter.srcAddress ) then
              luavbus.log ( 5, string.format ( "luavbus:waitData(): filter by srcAddress found 0x%04x", filter.srcAddress ) )    
              mask = bit32.bor( mask, 1 )
            end
          end
          if ( filter.dstAddress ~= nil ) then
            filtermask = bit32.bor(filtermask, 2)
            if ( vbus_packet.dstAddress == filter.dstAddress ) then
              luavbus.log ( DEBUG2, string.format ( "luavbus:waitData(): filter by dstAddress found 0x%04x", filter.dstAddress ) )    
              mask = bit32.bor( mask, 2 )
            end
          end
          if ( filter.command ~= nil ) then
            filtermask = bit32.bor(filtermask, 4)
            if ( vbus_packet.command == filter.command ) then
              luavbus.log ( DEBUG2, string.format ( "luavbus:waitData(): filter by command found 0x%04x", filter.command ) )
              mask = bit32.bor( mask, 4 )
            end
          end
          if ( mask == filtermask ) then
            luavbus.log ( DEBUG2, string.format ( "luavbus:waitData(): packet matchs all filters' condition (%d == %d)", mask, filtermask ) )
            table.insert(packets, vbus_packet)
            return packets
          else
            luavbus.log ( DEBUG2, string.format ( "luavbus:waitData(): packet didn't match all filters' condition (%d != %d)", mask, filtermask ) )
              
          end 
        end
      end
    end
  end
--  end
  until stop == true
  return nil
end

function luavbus:packetExtract ( data )
  luavbus.log ( DEBUG2, "luavbus:packetExtract(data)" )
  local buffer_length
  local index
  local sync_index
  local sync_found = 0
  -- local vbus_packet
  
  if ( data == nil ) then
    return nil
  end
  
  self.buffer = self.buffer..data
  buffer = self.buffer
  buffer_length = string.len(buffer)
  vbus_packet = nil
  vbus_packets = {}
  
  index = 1
  repeat
--  for index = 1, length, 1 do
    luavbus.log ( DEBUG4, string.format("Index %d length %d ",index, buffer_length))
    luavbus.log ( DEBUG4, string.format("Byte[%d]=0x%02x ",index, buffer:byte(index)))
    if buffer:byte(index) == 0xaa then
      luavbus.log ( DEBUG3, "Found sync byte at "..index )
      
      if sync_found == 1 then
        
        destination = buffer:byte(sync_index+2)+buffer:byte(sync_index+3)*256 
        source = buffer:byte(sync_index+4)+buffer:byte(sync_index+5)*256
        command = buffer:byte(sync_index+6)+buffer:byte(sync_index+6)*256
        payloads = buffer:byte(sync_index+8)
        checksum = buffer:byte(sync_index+9)
        

        if ( payloads ~= nil ) then
         luavbus.log ( DEBUG1, string.format ( "First sync already found at %d. Expected payload %d", sync_index, payloads ) )
        end
        expected_length = payloads*6+9
        if ( buffer_length < expected_length) then
          luavbus.log ( DEBUG2, string.format ( "Buffer doesn't contain yet the entire packet %d. Expected size %d", buffer_length, expected_length ) )
          break               
        end
--        luavbus.log ( DEBUG3, "First sync already found. This is the end of packet. The packet starts from " .. sync_index .. " and ends at " .. index )
--        vbus_packet = buffer:sub(sync_index,index-1)
        vbus_packet = buffer:sub(sync_index,sync_index+expected_length)
        table.insert(vbus_packets, vbus_packet)
        buffer = buffer:sub( index, string.len(buffer) )
        luavbus.log (DEBUG4, "Packet start "..sync_index.." end "..index-1 )
        luavbus.log (DEBUG3, string.format ( "luavbus:packetExtract(): vbus_packet dump %s", self.packetdump(vbus_packet) ) )
        sync_found = 0
        buffer_length = buffer_length - index + 1
        index = 0
        
        
        
        luavbus.log ( DEBUG2, string.format ( "Buffer %s, payload %s", self.packetdump(buffer), tostring(payloads) ) )
        
        header_length = 9
        buffer_length = string.len(buffer)


        if ( buffer_length < 9 ) then
          luavbus.log ( DEBUG2, string.format ( "Buffer (%d) is shorter than minimum frame size, needs to read some more bytes", buffer_length ) )
          break
         
        else
        
          payloads = buffer:byte(sync_index+8)
  
          expected_packet_length = payloads*6+header_length-sync_index
          luavbus.log ( DEBUG2, string.format ( "Sync found at position %d, payload %d, buffer length %d ", index, payloads, buffer_length ) )
          if ( expected_packet_length > buffer:len() ) then
            luavbus.log ( DEBUG2, string.format ( "Buffer does not contain the entire packet (buffer length: %d, expected packet length: %d", buffer_length, expected_packet_length ) )
          elseif ( expected_packet_length == buffer:len() ) then         
            luavbus.log ( DEBUG2, string.format ( "Buffer contains exactly the entire packer(buffer length: %d, expected packet length: %d", buffer_length, expected_packet_length ) )
          elseif ( expected_packet_length < buffer:len() ) then         
            luavbus.log ( DEBUG2, string.format ( "Buffer contains something more the entire packer(buffer length: %d, expected packet length: %d", buffer_length, expected_packet_length ) )      
          end
        end
      else
        if ( index ~= 1 ) then
          luavbus.log ( DEBUG3, "First sync not at position 1, cutting trailing garbage up to index " .. index-1 )
          buffer = buffer:sub( index, buffer_length )
          buffer_length = buffer_length - index + 1
          index = 0
          sync_index = 1
        else  
          sync_index = index
          sync_found = 1        
        end     
      end
    end
--  end
    index = index + 1
  until index == buffer_length
  self.buffer = buffer
  luavbus.log ( DEBUG2, string.format ( "luavbus:packetExtract(): remaining buffer %s", self.packetdump(buffer) ) )
  for k,v in pairs(vbus_packets) do
    luavbus.log ( DEBUG1, string.format ( "luavbus:packetExtract(): vbus_packet %d dump %s", k, self.packetdump(v) ) )
  end
  luavbus.log ( DEBUG1, string.format ( "luavbus:packetExtract(): returning %d packets", #vbus_packets ) )
  
  return vbus_packets
end

function luavbus:packetHandle ( packet )
  luavbus.log ( 5, string.format ( "luavbus:packetHandle ( packet ): handling packet %s", self:packetdump(vbus_packet) ) )
  -- print "VBusPacketHandl(packet)"
  local version;

  version = packet:byte(6)

  luavbus.log ( DEBUG1, string.format ("Packet version 0x%02x length %d", version, string.len(packet) ) )

  if version == 0x10 then
    self:packetHandleV1(packet)
  elseif version == 0x20 then
    self:packetHandleV2(packet)
  else
    luavbus.log ( WARN, string.format ("Unknown packet version 0x%02x", version ) )
  end

end

function luavbus:adjustSeptett ( data )
  local length 
  local septett
  local data_converted = ""
  length = string.len(data)
  septett = data:byte(length-1)
  checksum = data:byte(length)
  

  if ( string.len(data) == 0 ) then
    luavbus.log ( ERR, "Error packet length 0" )
    return data
  end
  for index = 0, length-3, 1 do
    local shifted = bit32.lshift(1, index)
    -- print ( "Shifted "..shifted)
    if ( ( bit32.band( septett, shifted) ) > 0 ) then
      local orred = bit32.bor( data:byte(index+1), 0x80)
      -- io.write ( string.format ( "Orred 0x%02x 0x%02x", orred, data:byte(index+1) ) )
      data_converted = data_converted..string.char(orred)
    else 
      data_converted = data_converted..string.char(data:byte(index+1))
    end
        end
  -- PacketDump(data_converted)
        
  return data_converted
end




function luavbus:packetHandleV1 ( packet )
  luavbus.log ( DEBUG3, "luavbus:packetHandleV1 ( packet ): starting" )
  local destination
  local source

  destination = packet:byte(2)+packet:byte(3)*256 
  source = packet:byte(4)+packet:byte(5)*256
  command = packet:byte(7)+packet:byte(8)*256
  payloads = packet:byte(9)
  checksum = packet:byte(10)
  
  luavbus.log ( DEBUG2, string.format ("Packet source 0x%04x destination 0x%04x command 0x%04x payloads %d checksum 0x%02x", source, destination, command, payloads, checksum ) )
  
  calc_checksum = self:packetCalculateChecksum(packet:sub(2,9))
  if checksum ~= calc_checksum then
    luavbus.log ( ERR, string.format ( "luavbus:packetHandleV1: Error wrong checksum (frame 0x%02x!=0x%02x calced)", checksum, calc_checksum ) )
    luavbus.log ( DEBUG1, string.format ( "luavbus:packetHandleV1: Dump: %s", self.packetdump(packet) ) )
  end
  
  self:readDevicesProfiles()
  local found = false 
  for k,v in pairs(self.profiles) do
    if source == tonumber(v.id) then
      -- print ( "Found ID "..v.id.." Name "..v.name)
      definition = v
      found = true
      break
    end

  end

  if not found then
    print ( "Unable to get device profiles" )
    return
  else
    if destination == 0x10 then
      self:packetV1Parse(packet, definition.objects )
    else
      print ( "Useless packet" )
    end 
  end

  -- if source == 0x7e11 and destination == 0x0010 then
  --  VBusPacketHandleMXData(packet)
  -- end
  return

end

function luavbus:packetParse ( packet )
  luavbus.log ( DEBUG2, string.format ( "luavbus:packetParse ( packet ): parsing packet %s", self:packetdump(vbus_packet) ) )
  -- print "VBusPacketHandl(packet)"
  local version;

  if ( packet == nil) then
    return nil
  end
  version = packet:byte(6)

  luavbus.log ( DEBUG2, string.format ("luavbus:packetParse(): Packet version 0x%02x length %d", version, string.len(packet) ) )

  if version == 0x10 then
    return self:packetParseV1(packet)
  elseif version == 0x20 then
    return self:packetParseV2(packet)
  else
    luavbus.log ( DEBUG2, string.format ("luavbus:packetParse(): Unknown packet version 0x%02x", version ) )
  end
  return nil
end

function luavbus:packetParseV1 ( packet )
  luavbus.log ( DEBUG3, "luavbus:packetParseV1 ( packet )" )
  
  vbp = luavbuspacket.new()
  luavbus.log (DEBUG4, string.format ( "luavbus:packetParseV1(): luavbuspacket address %s ", vbp ) )
  
--  mt = getmetatable ( vpb )
--  mt.__tostring = nil
--  setmetatable ( vpb, mt )
--  vbp.__tostring = nil
  luavbus.log ( DEBUG3, string.format(  "luavbus:packetParseV1 ( packet ): packet address %s ", vbp ) )
--  vbp.__tostring = luavbuspacket.tostring
  
  vbp.dstAddress = packet:byte(2)+packet:byte(3)*256 
  vbp.srcAddress = packet:byte(4)+packet:byte(5)*256
  vbp.version = packet:byte(6)
  vbp.command = packet:byte(7)+packet:byte(8)*256
  vbp.payloads = packet:byte(9)
  vbp.checksum = packet:byte(10)
  vbp.payloadsData = ""

  local data = ""
  payloads = packet:byte(9)
  checksum = packet:byte(10)
  self.datacount = self.datacount + 1
  
  calc_checksum = self:packetCalculateChecksum(packet:sub(2,9))
  if checksum ~= calc_checksum then
    luavbus.log ( WARN, string.format ( "luavbus:packetParseV1(): Error wrong checksum (frame 0x%02x!=0x%02x calced)", checksum, calc_checksum ) )
    luavbus.log ( DEBUG1, string.format ( "luavbus:packetParseV1(): Dump: %s", self.packetdump(packet) ) )
    return nil
  end
  luavbus.log ( DEBUG3,  string.format("luavbus:packetParseV1(): payloads: %d", payloads) )
  for payload_index = 0, payloads-1, 1 do
    local offset = 11+(payload_index*6);
    local payload = packet:sub(offset,offset+5)
    local septett = packet:byte(offset+4)
    local checksum = packet:byte(offset+5)
    
    calc_checksum = self:packetCalculateChecksum(payload:sub(1,string.len(payload)-1))
    
    if checksum ~= calc_checksum then
      if ( checksum == nil or calc_checksum == nil ) then
        luavbus.log ( WARN, string.format ( "luavbus:packetParseV1(): payload %d: septett error wrong checksum (%s!=0x%02x)", payload_index, tostring(checksum), tostring(calc_checksum) ) )
      end
      
      luavbus.log ( DEBUG1, string.format ( "luavbus:packetParseV1(): payload %d: septett Error wrong checksum (frame 0x%02x!=0x%02x calced)", payload_index, checksum, calc_checksum ) )
      luavbus.log ( DEBUG1, string.format ( "Packet dump: %s", luavbus.packetdump(packet) ) )
      luavbus.log ( DEBUG1, string.format ( "Payload %d dump: %s", payload_index, luavbus.packetdump(payload) ) )

      return nil
    end

    if ( septett ~= 0x00 ) then
      luavbus.log ( DEBUG3, "Payload need to be adjusted with septett" )
      payload = self:adjustSeptett ( payload )
    else
      payload = payload:sub (1,4)
    end
    data = data..payload
--    table.insert ( vbp.payloadsData, payload )
    vbp.payloadsData = vbp.payloadsData..payload 
  end
  local printed = 0

--  debug ( 5, string.format ( "Packet source %s destination %s command %s payloads %s checksum %s", tostring(vbp.srcAddress), tostring(vbp.dstAddress), tostring(vbp.command), tostring(vbp.payloads), tostring(vbp.checksum) ) )
  
  return vbp 
end

function luavbus:packetParseV2 ( packet )
  luavbus.log ( 5, "luavbus:packetParseV2 ( packet )" )
  local destination
  local source
  local command
  local payloads
  local checksum
  
  if ( packet:len() < 10 ) then
    print ( "Wrong packet length"..packet:len())
  end
  
  destination = packet:byte(2)+packet:byte(3)*256 
  source = packet:byte(4)+packet:byte(5)*256
  command = packet:byte(7)+packet:byte(8)*256
  payloads = packet:byte(9)
  checksum = packet:byte(10)
  calc_checksum = self:packetCalculateChecksum(packet:sub(2,16))
  if checksum ~= calc_checksum then
    luavbus.log ( 5, string.format ( "luavbus:packetParseV2(): V2 Error wrong checksum (0x%02x!=0x%02x)", checksum, calc_checksum ) )
    self.packetdump(packet)
  end
  luavbus.log ( DEBUG3, string.format ("luavbus:packetParseV2(): Packet source 0x%04x destination 0x%04x command 0x%04x payloads %d checksum 0x%02x", source, destination, command, payloads, checksum ) )
  return

end

function luavbus:packetHandleV2 ( packet )
  luavbus.log ( 1, "luavbus:HandleV2 ( packet )" )
  local destination
  local source
  local command
  local payloads
  local checksum
  
  if ( packet:len() < 10 ) then
    luavbus.log ( WARN, "Wrong packet length"..packet:len())
  end
  
  destination = packet:byte(2)+packet:byte(3)*256 
  source = packet:byte(4)+packet:byte(5)*256
  command = packet:byte(7)+packet:byte(8)*256
  payloads = packet:byte(9)
  checksum = packet:byte(10)
  calc_checksum = self:packetCalculateChecksum(packet:sub(2,16))
  if checksum ~= calc_checksum then
    luavbus.log ( DEBUG2, string.format ( "V2 Error wrong checksum (0x%02x!=0x%02x)", checksum, calc_checksum ) )
    self.packetdump(packet)
  end
  luavbus.log ( DEBUG2, string.format ("Packet source 0x%04x destination 0x%04x command 0x%04x payloads %d checksum 0x%02x", source, destination, command, payloads, checksum ) )
  return

end

function luavbus:readDevicesProfiles ( profiles_dir )
  if ( profiles_dir ~= nil ) then
    for profile_file in lfs.dir(profiles_dir) do
      if lfs.attributes(profiles_dir..profile_file,"mode") == "file" then
        if extension == "json" then
          print ( "File: "..path..filename )
        end
        device_profile = io.open(profiles_dir.."/"..profile_file, "rb")
        content = device_profile:read("*all")
        -- print ( "Content:" .. content )
        content = v
        decoded = cjson.decode(content)
        for k, v in pairs( decoded ) do
           print(k, v)
        end
        table.insert(self.profiles,decoded)
        device_profile:close()
      end
    end
  else
    for k,vbusprofile in pairs(vbusprofiles) do
      content = vbusprofile
      decoded = cjson.decode(content)

      table.insert(self.profiles,decoded)
    end
  end
end

function luavbus:packetCalculateChecksum ( data )
  local index
  local crc = 0x7f

  -- print "VBusPacketChecksum(data)"
  for index = 1,  string.len(data), 1 do
    crc = bit32.band( crc - data:byte(index),0x7f)
    -- print ( "CRC " .. crc )
  end

  luavbus.log ( DEBUG2, string.format ( "luavbus:packetCalculateChecksum ( data ): checksum 0x%02x",crc ) )
  if crc == nil then
    luavbus.log ( WARN, "Error calculating checksum" )
    crc = nil
  end
  return crc
end

function luavbus.packetdump(packet)
  local length
  local hexdump
  local dump_string = ""
  if ( packet == nil ) then
      dump_string = "luavbus.packetdump(): nil packet"
      return dump_string
  end
  
  if ( type(packet) == "table" ) then
      luavbus.log ( DEBUG4, "luavbus.packetdump(): table packet " .. #packet)
      dump_string = "luavbus.packetdump(): table packet"
      dump_string = dump_string .. " length " .. #packet .. " "
      -- for index = 1, #packet, 1 do
      for i, v in ipairs(packet) do
--        dump_string = dump_string .. string.format( '0x%02x ', packet[index]:byte( 1 ), packet[index]:byte( 1 ) )
        luavbus.log ( DEBUG4, "luavbus.packetdump(): index " .. i .. " value " .. v:byte())
        dump_string = dump_string .. string.format( '0x%02x ', v:byte( 1 ) )  
        
      end
      
      return dump_string
  end
  
  length = string.len ( packet )
  
  luavbus.log ( DEBUG4, "luavbus.packetdump(): packet "..packet)
  dump_string = dump_string .. " length " .. length .. " "
  -- print ( "Packet length: "..length.."" )
  for i = 1, length, 1 do
    dump_string = dump_string .. string.format('0x%02X ',string.byte(packet,i) )
  end
  luavbus.log ( DEBUG4,  dump_string )
  return dump_string
  

end

ERR, WARN, INFO, DEBUG1, DEBUG2, DEBUG3, DEBUG4, DEBUG5 = 1, 2, 3, 4, 5, 6, 7, 8

function luavbus.log ( level, ... )
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

return luavbus