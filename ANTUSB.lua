-- ANT protocol dissector for Wireshark
--
-- Written by dcast78 <dcast78@gmail.com>
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, see <http://www.gnu.org/licenses/>.

-- Usage: wireshark -X lua_script:ANTUSB.lua 
-- For complete trace analysis
--
-- Usage: wireshark -X lua_script:ANTUSB.lua -R "usbant"
-- For specific ANT protocol analysis
--
-- It is not advisable to install this dissector globally, since
-- it will try to interpret the communication of any USB device
-- using the vendor-specific interface class.

-- Not fully complete protocol decoding work in progress...

-- Create custom protocol for the ANT analyzer.
p_usbant = Proto("USBANT", "USB ANT stick protocol")

-- List of packet decoding variables from "ANT Message Protocol and Usage"
-- refer to  https://www.thisisant.com/developer/resources/downloads#documents_tab 
-- for complete protocol documentation

-- On section 7.1 "message structure" 
-- ##############################################........######################
-- #            #            #            #                      #            #
-- #    Sync    #    Msg     # Message ID #   Message content    #  Checksum  #
-- # (fix val)  #   Length   #            #  (Bytes 0 - (N -1))  #   XOR      #
-- #    0xA4    #   1 byte   #     id     #     var data_N       #  1 byte    #
-- #            #            #            #                      #            #
-- ##############################################........######################


local id = {
    [0x00] = "Invalid",
    [0x3E] = "ANT Version",
    [0x40] = "Channel Response of Message ID ",
    [0x41] = "Unassign Channel - Config",
    [0x42] = "Assign Channel - Config",
    [0x43] = "Set Channel Period",
    [0x44] = "Set Search Timeout",
    [0x45] = "Set Channel RF Frequency",
    [0x46] = "Set Network - Config",
    [0x47] = "Set Transmit Power",
    [0x48] = "CW Test - Test",
    [0x4A] = "System Reset - Control",
    [0x4B] = "Open Channel - Control",
    [0x4C] = "Close Channel - Control",
    [0x4D] = "Request Message - Control",
    [0x4E] = "Broadcast Data - Data",
    [0x4F] = "Acknowledge Data - Data",
    [0x50] = "Burst Transfer - Data",
    [0x51] = "Set Channel ID - Config",
    [0x51] = "Channel ID - Requested Response",
    [0x52] = "Channel Status - Requested Response",
    [0x53] = "CW Init",
    [0x54] = "Capabilities",
    [0x59] = "ID List Add - Config",
    [0x5A] = "ID List Config - Config",
    [0x5B] = "Open Rx Scan Mode - Control",
    [0x60] = "Set Channel Transmit Power - Config",
    [0x61] = "Serial Number - Requested Response",
    [0x63] = "Set Low Priority Search Timeout - Config",
    [0x65] = "Set Serial Number Set Channel ID - Config",
    [0x66] = "Enable Ext RX Mesgs - Config",
    [0x68] = "Enable LED - Config",
    [0x6D] = "Crystal Enable - Config",
    [0x6E] = "Lib Config - Config",
    [0x6F] = "Startup Message - Notifications",
    [0x70] = "Frequency Agility - Config",
    [0x71] = "Set Proximity Search - Config",
    [0x75] = "Set Channel Search Priority - Config",
    [0xAE] = "Serial Error Message - Notifications",
    [0xC5] = "Sleep Message - Control"
}

local data_1 = {
    [0x3E] = "Ver0",
    [0x40] = "Channel Number",
    [0x41] = "Channel Number",
    [0x42] = "Channel Number",
    [0x43] = "Channel Number",
    [0x44] = "Channel Number",
    [0x45] = "Channel Number",
    [0x46] = "Net #",
    [0x47] = "0",
    [0x48] = "0",
    [0x4A] = "0",
    [0x4B] = "Channel Number",
    [0x4C] = "Channel Number",
    [0x4D] = "Channel Number",
    [0x4E] = "Channel Number",
    [0x4F] = "Channel Number",
    [0x50] = "Sequence/Channel Number",
    [0x51] = "Channel Number",
    [0x51] = "Channel Number",
    [0x52] = "Channel Number",
    [0x53] = "0",
    [0x54] = "Max Channels",
    [0x59] = "Channel Number",
    [0x5A] = "Channel Number",
    [0x5B] = "0",
    [0x60] = "Channel Number",
    [0x61] = "Serial Number(1/4)",
    [0x63] = "Channel Number",
    [0x65] = "Channel Number",
    [0x66] = "0",
    [0x68] = "0",
    [0x6D] = "0",
    [0x6E] = "0",
    [0x6F] = "Startup Message ",
    [0x70] = "Channel Number",
    [0x71] = "Channel Number",
    [0x75] = "Channel Number",
    [0xAE] = "Error Number ",
    [0xC5] = "0"
}

local data_2 = {
    [0x3E] = "Ver1",
    [0x40] = "Message ID",
    [0x42] = "Channel Type",
    [0x43] = "Messaging Period(1/2)",
    [0x44] = "Search Timeout",
    [0x45] = "RF Frequency",
    [0x46] = "Key 0",
    [0x47] = "TX Power",
    [0x48] = "TX Power",
    [0x4D] = "Message ID",
    [0x4E] = "Data0",
    [0x4F] = "Data0",
    [0x50] = "Data0",
    [0x51] = "Device number(1/2)",
    [0x51] = "Device number(1/2)",
    [0x52] = "Channel Status",
    [0x54] = "Max Networks",
    [0x59] = "Device number(1/2)",
    [0x5A] = "List Size",
    [0x60] = "TX Power",
    [0x61] = "Serial Number(2/4)",
    [0x63] = "Search Timeout",
    [0x65] = "Device Type ID",
    [0x66] = "Enable",
    [0x68] = "Enable",
    [0x6E] = "Lib Config",
    [0x70] = "Freq’ 1",
    [0x71] = "Search Threshold",
    [0x75] = "Search Priority"
}

local data_3 = {
    [0x3E] = "Ver2",
    [0x40] = "Message Code",
    [0x42] = "Network Number",
    [0x43] = "Messaging Period(2/2)",
    [0x46] = "Key 1",
    [0x48] = "RF Freq",
    [0x4E] = "Data1",
    [0x4F] = "Data1",
    [0x50] = "Data1",
    [0x51] = "Device number(2/2)",
    [0x51] = "Device number(2/2)",
    [0x54] = "Standard Options",
    [0x59] = "Device number(2/2)",
    [0x5A] = "Exclude",
    [0x61] = "Serial Number(3/4)",
    [0x65] = "Trans. Type",
    [0x70] = "Freq 2"
}

local data_4 = {
    [0x3E] = "Ver 3|Ver 4",
    [0x42] = "[Extended Assign’t]",
    [0x46] = "Key 2",
    [0x4E] = "Data2",
    [0x4F] = "Data2",
    [0x50] = "Data2",
    [0x51] = "Device Type ID",
    [0x51] = "Device Type ID",
    [0x54] = "Advanced Options",
    [0x59] = "Device Type ID",
    [0x61] = "Serial Number(4/4)",
    [0x70] = "Freq 3"
}

local data_5 = {
    [0x3E] = "Ver 5/Ver6",
    [0x46] = "Key 3",
    [0x4E] = "Data3",
    [0x4F] = "Data3",
    [0x50] = "Data3",
    [0x51] = "Trans. Type",
    [0x51] = "Man ID",
    [0x54] = "Adv Options 2",
    [0x59] = "Trans. Type"
}

local data_6 = {
    [0x3E] = "Ver7",
    [0x46] = "Key 4",
    [0x4E] = "Data4",
    [0x4F] = "Data4",
    [0x50] = "Data4",
    [0x54] = "Rsvd",
    [0x59] = "List Index"
}

local data_7 = {
    [0x3E] = "Ver8",
    [0x46] = "Key 5",
    [0x4E] = "Data5",
    [0x4F] = "Data5",
    [0x50] = "Data5"
}

local data_8 = {
    [0x3E] = "Ver9",
    [0x46] = "Key 6",
    [0x4E] = "Data6",
    [0x4F] = "Data6",
    [0x50] = "Data6"
}

local data_9 = {
    [0x3E] = "Ver10 ",
    [0x46] = "Key 7 ",
    [0x4E] = "Data7 ",
    [0x4F] = "Data7 ",
    [0x50] = "Data7 "
}

local data_10 = {
    [0x3E] = "Ver10 ",
    [0x46] = "Key 7 ",
    [0x4E] = "Data7 ",
    [0x4F] = "Data7 ",
    [0x50] = "Data7 "
}

-- On section 9.3 "ANT Message Summary" detail of 0x40 Channel Event/Channel Response Message ID
-- #########################################################################################
-- #            #            #            #           #           #           #            #
-- #    Sync    #    Msg     # Message ID #  Channel  # Prev msg  # message_  #  Checksum  #
-- # (fix val)  #   Length   #            #   Num     # ref resp  #  codes    #   XOR      #
-- #    0xA4    #   3 byte   #     0x40   #  1 byte   # 1 byte    # this var  #  1 byte    #
-- #            #            #            #           #           #           #            #
-- #########################################################################################


local message_codes = {
    [0x00] = "RESPONSE_NO_ERROR - Returned on a successful operation" ,
    [0x01] = "EVENT_RX_SEARCH_TIMEOUT - A receive channel has timed out on searching. The search is terminated" ,
    [0x02] = "EVENT_RX_FAIL - A receive channel missed a message which it was expecting. This would happen when a receiver is tracking a transmitter and is expecting a message at the set message rate." ,
    [0x03] = "EVENT_TX - A Broadcast message has been transmitted successfully. This event should be used to send the next message for transmission to the ANT device if the node is setup as a transmitter." ,
    [0x04] = "EVENT_TRANSFER_RX_FAILED - A receive transfer has failed. This occurs when a Burst Transfer Message was incorrectly received." ,
    [0x05] = "EVENT_TRANSFER_TX_COMPLETED - An Acknowledged Data message or a Burst Transfer sequence has been completed successfully. When transmitting Acknowledged Data or Burst Transfer" ,
    [0x06] = "EVENT_TRANSFER_TX_FAILED - An Acknowledged Data message or a Burst Transfer Message has been initiated and the transmission has failed to complete successfully" ,
    [0x07] = "EVENT_CHANNEL_CLOSED - The channel has been successfully closed. When the Host sends a message to close a channel, it first receives a RESPONSE_NO_ERROR to indicate that the message was successfully received by ANT. This event is the actual indication of the closure of the channel. So, the Host must use this event message instead of the RESPONSE_NO_ERROR message to let a channel state machine continue. " ,
    [0x08] = "EVENT_RX_FAIL_GO_TO_SEARCH - The channel has dropped to search after missing too many messages." ,
    [0x09] = "EVENT_CHANNEL_COLLISION - Two channels have drifted into each other and overlapped in time on the device causing one channel to be blocked. " ,
    [0x0A] = "EVENT_TRANSFER_TX_START - A burst transfer has begun / ANT Library special event (Not in serial interface). This event is sent to denote a valid broadcast data message has been received by the ANT library" ,
    [0x0B] = "ANT Library special event (Not in serial interface). This event is sent to denote that a valid acknowledged data message has been received by the ANT library" ,
    [0x0C] = "ANT Library special event (Not in serial interface). It indicates the successful reception of a burst packet in a Burst Transfer sequence." ,
    [0x15] = "CHANNEL_IN_WRONG_STATE - Returned on attempt to perform an action on a channel that is not valid for the channel's state" ,
    [0x16] = "CHANNEL_NOT_OPENED - Attempt to transmit data on an unopened channel" ,
    [0x18] = "CHANNEL_ID_NOT_SET - Returned on attempt to open a channel before setting a valid ID" ,
    [0x19] = "CLOSE_ALL_CHANNELS - Returned when an OpenRxScan() command is sent whileother channels are open. " ,
    [0x1F] = "TRANSFER_IN_PROGRESS - Returned on an attempt to communicate on a channel with a transmit transfer in progress." ,
    [0x20] = "TRANSFER_SEQUENCE_NUMBER_ERROR - Returned when sequence number is out of order on a Burst Transfer" ,
    [0x21] = "TRANSFER_IN_ERROR - Returned when a burst message passes the sequence number check but will not be transmitted. " ,
    [0x28] = "INVALID_MESSAGE - Returned when message has invalid parameters" ,
    [0x29] = "INVALID_NETWORK_NUMBER - Returned when an invalid network number is provided. As mentioned earlier" ,
    [0x30] = "INVALID_LIST_ID - Returned when the provided list ID or size exceeds the limit." ,
    [0x31] = "INVALID_SCAN_TX_CHANNEL - Returned when attempting to transmit on ANT channel 0 in scan mode." ,
    [0x40] = "NVM_FULL_ERROR - Returned when the NVM for SensRcore mode is full." ,
    [0x41] = "NVM_WRITE_ERROR - Returned when writing to the NVM for SensRcore modefails." 
}

-- Wireshark dissector code

-- Create the fields exhibited by the protocol.
p_usbant.fields.sync     = ProtoField.uint8("usbant.msgsync", "Sync BYTE", base.HEX_DEC)
p_usbant.fields.msglength= ProtoField.uint8("usbant.msglen", "Message Length", base.DEC)
p_usbant.fields.msgid    = ProtoField.uint8("usbant.msgid", "Message Id", base.HEX_DEC, id, nil, "Message  ID")
p_usbant.fields.msgdata1 = ProtoField.uint8("usbant.msgdata1", "Message Data 1", base.HEX)
p_usbant.fields.msgdata2 = ProtoField.uint8("usbant.msgdata2", "Message Data 2", base.HEX)
p_usbant.fields.msgdata3 = ProtoField.uint8("usbant.msgdata3", "Message Data 3", base.HEX)
p_usbant.fields.msgdata4 = ProtoField.uint8("usbant.msgdata4", "Message Data 4", base.HEX)
p_usbant.fields.msgdata5 = ProtoField.uint8("usbant.msgdata5", "Message Data 5", base.HEX)
p_usbant.fields.msgdata6 = ProtoField.uint8("usbant.msgdata6", "Message Data 6", base.HEX)
p_usbant.fields.msgdata7 = ProtoField.uint8("usbant.msgdata7", "Message Data 7", base.HEX)
p_usbant.fields.msgdata8 = ProtoField.uint8("usbant.msgdata8", "Message Data 8", base.HEX)
p_usbant.fields.msgdata9 = ProtoField.uint8("usbant.msgdata9", "Message Data 9", base.HEX)
p_usbant.fields.msgdata10 = ProtoField.uint8("usbant.msgdata10", "Message Data 10", base.HEX)
p_usbant.fields.msgdata11 = ProtoField.uint8("usbant.msgdata11", "Message Data 11", base.HEX)
p_usbant.fields.msgdata12 = ProtoField.uint8("usbant.msgdata12", "Message Data 12", base.HEX)
p_usbant.fields.msgdata13 = ProtoField.uint8("usbant.msgdata13", "Message Data 12", base.HEX)
p_usbant.fields.checksum  = ProtoField.uint8("usbant.checksum", "XOR checksum", base.HEX)
p_usbant.fields.unknown   = ProtoField.bytes("usbant.unknown", "Unidentified message data")

-- Referenced USB URB dissector fields.
local f_urb_type = Field.new("usb.urb_type")
local f_transfer_type = Field.new("usb.transfer_type")
local f_endpoint = Field.new("usb.endpoint_number.endpoint")

-- Insert warning for undecoded leftover data.
local function warn_undecoded(tree, range)
    local item = tree:add(p_usbant.fields.unknown, range)
    item:add_expert_info(PI_UNDECODED, PI_WARN, "Leftover data")
end

-- Last packet checksum "XOR of all previous bytes including the SYNC byte"
-- function to add byte visualization of last Byte on protocol tree
local function checksum(tree, range)
    local item = tree:add(p_usbant.fields.checksum, range(range:len()-1,1))
end

--find data packet field interpretation based on "Appendix A – ANT Message Details" of "ANT Message Protocol and Usage" document 
local function data_packet(packet_n,msg_id,msg_data_3)
   local  data_type = "description not found"
   if packet_n == 1 then
      data_type=data_1[msg_id]
   elseif packet_n == 2 then   -- Handler specific for pachet type 0x40 warning user to data packet contest
      if msg_id == 0x40 then
        data_type="response referered of previous Message ID packet"  
      else 
        data_type=data_2[msg_id]
      end
   elseif packet_n == 3 then
      if msg_id == 0x40 then    -- Handler specific for pachet type 0x40 (Data packet 2 contain refernce, packet 3 result message)
        data_type=message_codes[msg_data_3]  
      else 
        data_type=data_3[msg_id]
      end
   elseif packet_n == 4 then
      data_type=data_4[msg_id]
   elseif packet_n == 5 then
      data_type=data_5[msg_id]
   elseif packet_n == 6 then
      data_type=data_6[msg_id]
   elseif packet_n == 7 then
      data_type=data_7[msg_id]
   elseif packet_n == 8 then
      data_type=data_8[msg_id]
   elseif packet_n == 9 then
      data_type=data_9[msg_id]
   elseif packet_n == 10 then
      data_type=data_10[msg_id]
  end
  if data_type == nil then
     return "Packet description not found"
  else
     return data_type
  end
end


-- Dissect ANT control command messages.
-- range contain all the packets including checksum
-- pinfo info field on top frame
-- tree ont ANT protcol analysis central frame
local function dissect_command(range, pinfo, tree)
    local subtree = tree:add(p_usbant, range(), "ANT")

    -- assign to command first part N-1 packets to exclude checksum on analysis
    local command = range(0,range:len()-1) 
    
    -- add to tree first Byte with fix value 0xA4
    tree:add_le(p_usbant.fields.sync, command(0,1))

    -- add to tree second Byte it contain message packet count
    tree:add_le(p_usbant.fields.msglength, command(1,1))
    -- n_msg_len=command(1,1):le_uint()

    if command:len() >= 2 then
    tree:add_le(p_usbant.fields.msgid, command(2,1))
    msg_id=tonumber(string.format("%02X",command(2,1):le_uint()),16)
    pinfo.cols.info = string.format("0x%02X - %s ",
					    command(2,1):le_uint(), id[msg_id])
    end

    if command:len() >= 3 then
    tree:add_le(p_usbant.fields.msgdata1, command(3,1))
    tree:add_le(command(3,1), "   Data packet 1: " .. data_packet(1,msg_id),"")
    end 

    if command:len() >= 4 then
    tree:add_le(p_usbant.fields.msgdata2, command(4,1))
    tree:add_le(command(4,1), "   Data packet 2: " .. data_packet(2,msg_id),"")
    if msg_id == 0x40 then
      pinfo.cols.info:append(" " ..  string.format("0x%02X" , command(4,1):le_uint()))
    end 
    end

    if command:len() >= 5 then
    tree:add_le(p_usbant.fields.msgdata3, command(5,1))
    tree:add_le(command(5,1), "   Data packet 3: " .. data_packet(3,msg_id, tonumber(string.format("%02X",command(5,1):le_uint()),16)))
    end

    if command:len() > 6 then
    tree:add_le(p_usbant.fields.msgdata4, command(6,1))
    tree:add_le(command(6,1), "   Data packet 4: " .. data_packet(4,msg_id),"")
    end

    if command:len() > 7 then
    tree:add_le(p_usbant.fields.msgdata6, command(7,1))
    tree:add_le(command(7,1), "   Data packet 5: " .. data_packet(5,msg_id),"")
    end

    if command:len() > 8 then
    tree:add_le(p_usbant.fields.msgdata6, command(8,1))
    tree:add_le(command(8,1), "   Data packet 6: " .. data_packet(6,msg_id),"")
    end

    if command:len() > 9 then
    tree:add_le(p_usbant.fields.msgdata7, command(9,1))
    tree:add_le(command(9,1), "   Data packet 7: " .. data_packet(7,msg_id),"")
    end

    if command:len() > 10 then
    tree:add_le(p_usbant.fields.msgdata8, command(10,1))
    tree:add_le(command(10,1), "   Data packet 8: " .. data_packet(8,msg_id),"")
    end

    checksum(tree, range(2))
    return 2
end

-- Main ANT dissector function.
function p_usbant.dissector(tvb, pinfo, tree)
    local transfer_type = tonumber(tostring(f_transfer_type()))
   -- local urb_type = tonumber(tostring(f_urb_type()))
    local endpoint = tonumber(tostring(f_endpoint()))

    -- Bulk transfers only.
    if (transfer_type == 3 and endpoint == 1) then
            -- pinfo.cols.protocol = p_usbant.name
            pinfo.cols.protocol = "ANT"
            local subtree = tree:add(p_usbant, tvb(), "ANT")
            subtree:add(p_usbant.fields.msgtype, endpoint):set_generated()
            return dissect_command(tvb, pinfo, subtree)
    end
    return 0
end

-- Register ANT protocol dissector during initialization.
function p_usbant.init()
--    local usb_product_dissectors = DissectorTable.get("usb.product")

    -- Dissection by vendor+product ID requires that Wireshark can get the
    -- the device descriptor.  Making a USB device available inside VirtualBox
    -- will make it inaccessible from Linux, so Wireshark cannot fetch the
    -- descriptor by itself.  However, it is sufficient if the VirtualBox
    -- guest requests the descriptor once while Wireshark is capturing.
--    usb_product_dissectors:add(0x29616688, p_usbant) -- SysClk ANT1016
--    usb_product_dissectors:add(0x29616689, p_usbant) -- SysClk ANT1034

    -- Addendum: Protocol registration based on product ID does not always
    -- work as desired.  Register the protocol on the interface class instead.
    -- The downside is that it would be a bad idea to put this into the global
    -- configuration, so one has to make do with -X lua_script: for now.
    local usb_bulk_dissectors = DissectorTable.get("usb.bulk")

    -- For some reason the "unknown" class ID is sometimes 0xFF and sometimes
    -- 0xFFFF.  Register both to make it work all the time.
    usb_bulk_dissectors:add(0xFF, p_usbant)
    usb_bulk_dissectors:add(0xFFFF, p_usbant)
end

