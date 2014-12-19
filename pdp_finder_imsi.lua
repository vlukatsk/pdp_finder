--[[
    19.12.2014 - added support of different diameter cmd codes
    19.12.2014 - added support of the reject codes for gtp

--]]
do
    os.setlocale('C')
    imsi = 0
    const_gtp_port = '2123'
    const_rad_auth_port = '1812'
    const_rad_acct_port = '1813'
    const_diam_gx_port = '3868'
    const_diam_gy_port = '3868'
    const_rad_delay = '15' 

    local first_run = true
    packet_list = {}
    --[[
        packet_list{packet.number}
            ismi  =
    --]]
    
    -- declare our pseudo-protocols
    pdp_proto = Proto("pdp","PDP Finder Data")
    -- add the field to the protocol
    imsi_field = ProtoField.string("pdp.imsi","IMSI")
    -- id_field = ProtoField.uint16("pdp.id","PDP-ID")
    pdp_proto.fields = {imsi_field}
    local original_gtp_dissector = 0 
    local original_diam_dissector = 0 
    local original_rad_auth_dissector = 0 
    local original_rad_acct_dissector = 0 
   
    local frame_time          = Field.new("frame.time_epoch")
    local frame_number        = Field.new("frame.number") 
    
    local ip_proto            = Field.new("ip.proto")
    local tcp_port            = Field.new("tcp.port")
    local udp_port            = Field.new("udp.port")
    
    local gtp_imsi            = Field.new("gtp.imsi")
    local gtp_type            = Field.new("gtp.message")
    local gtp_teid_cp         = Field.new("gtp.teid_cp")
    local gtp_teid            = Field.new("gtp.teid")
    local gtp_seq_number      = Field.new("gtp.seq_number")
    local gtp_charging_id     = Field.new("gtp.chrg_id")
    local gtp_cause           = Field.new("gtp.cause")
    
    local diam_imsi           = Field.new("diameter.Subscription-Id-Data")
    local diam_session_id     = Field.new("diameter.Session-Id")
    local diam_request        = Field.new("diameter.flags.request")
    local diam_cc_type        = Field.new("diameter.CC-Request-Type")
    local diam_app            = Field.new("diameter.applicationId")
    local diam_cmd            = Field.new("diameter.cmd.code")
     
    local rad_code            = Field.new("radius.code")
    local rad_imsi            = Field.new("radius.3GPP_IMSI")
    local rad_id              = Field.new("radius.id")
   
    
    
    local seq_number = 0
    local sgsn_teid = 0
    local gw_teid = 0
    local charging_id = 0
    local call_diam_session_id = {}
    call_diam_session_id['16777238'] = false
    call_diam_session_id['4'] = false
    local rad_message = {}

    -- function to display debug messages    
    local function debug_log (flag, num, fl_gtp, fl_diam, fl_rad, text)
        if flag then
            warn("Frame: ".. tostring(num) .. "\n" .. text)
            io.write("Frame: ".. tostring(num) .. "\n" .. text .. "\n")
            if fl_gtp then
                warn("gtp seq: " .. seq_number) 
                warn("gtp sgsn teid: " .. sgsn_teid)
                warn("gtp gw teid: " .. gw_teid)
                warn("gtp charging id: " .. charging_id)


                io.write("gtp seq: " .. seq_number .."\n") 
                io.write("gtp sgsn teid: " .. sgsn_teid .."\n")
                io.write("gtp gw teid: " .. gw_teid .."\n")
                io.write("gtp charging id: " .. charging_id .."\n")
            end
            if fl_diam then
                for i,s in pairs(call_diam_session_id) do
                    warn("diam sess id[".. tostring(i) .."]: " .. tostring(s))
                    io.write("diam sess id[".. tostring(i) .."]: " .. tostring(s) .."\n")
                end
            end
            if fl_rad then
                for i,r in pairs(rad_message) do
                    warn("rad id[".. i .."] received on " .. tostring(r['time']))
                    io.write("rad id[".. i .."] received on " .. tostring(r['time']) .. "\n")
                end
            end
            io.write('\n')
            warn('\n')
        end
    end

    local function imsi_find_radius_packets(l_imsi)
        local l_frame_number        = tostring(frame_number())
        local l_rad_code            = tostring(rad_code())
        local logging = false  
        -- if it is a request (1 = Access-Request, 4 = Acct-Request)
        if l_rad_code == '1' or l_rad_code == '4' then
            local l_rad_imsi = tostring(rad_imsi())
            debug_log(logging, l_frame_number, false,false,true,'RADIUS Request\nbefore')
            
            -- if imsi matches
            --      capture id and time
            --      record packet
            if l_rad_imsi == l_imsi then
                local l_rad_id = tostring(rad_id())
                local l_frame_time = tostring(frame_time())
                rad_message[l_rad_id] = {}
                rad_message[l_rad_id]['time'] = l_frame_time
                packet_list[l_frame_number] = {}
                packet_list[l_frame_number]['imsi'] = l_imsi
            end
            
            debug_log(logging,l_frame_number, false,false,true,'RADIUS Request\nafter')

        -- if it is an answer ( 2 - Access Accept, 3 - Access Reject, 5 Acct Accept
        elseif l_rad_code == '2' or l_rad_code == '3' or  l_rad_code == '5' then
                local l_rad_id = tostring(rad_id())
                local l_frame_time = tostring(frame_time())
                
                debug_log(logging,l_frame_number,false,false,true,'RADIUS Response\nbefore')
                
                if rad_message[l_rad_id] then
                    if ( tonumber(l_frame_time) - tonumber(rad_message[l_rad_id]['time']) ) < (tonumber(const_rad_delay)*1000) then
                        packet_list[l_frame_number] = {}
                        packet_list[l_frame_number]['imsi'] = l_imsi 
                        rad_message[l_rad_id] = nil
                    else
                        rad_message[l_rad_id] = nil
                    end
                end
                
                debug_log(logging,l_frame_number,false,false,true,'RADIUS Response\nafter')
        end
    end


    local function imsi_find_diam_packets(l_imsi)
        local l_frame_number        = tostring(frame_number())
        local l_diam_cmd            = tostring(diam_cmd())
        local logging = false 
        debug_log(logging,l_frame_number,false,true,false,'CMD:'.. l_diam_cmd ..'\nbefore')
        -- CCR/CCA - credit control 
        if l_diam_cmd == '272' then
            local l_diam_app = tostring(diam_app())
            local l_packet_cc_type      = tostring(diam_cc_type())
            -- if session-id is already known
            if call_diam_session_id[l_diam_app] then
                -- if session id matches
                --      mark the packet
                local l_diam_session_id = tostring(diam_session_id())
                

                if l_diam_session_id == call_diam_session_id[l_diam_app] then
                    packet_list[l_frame_number] = {}
                    packet_list[l_frame_number]['imsi'] = l_imsi
                    --[[
                    if this message is termination answer then clear call_diam_session_id
                    --]]
                    local l_diam_request = tostring(diam_request())
                    if (l_diam_request == '0') and (l_packet_cc_type == '3') then
                        call_diam_session_id[l_diam_app] = false 
                    end
                end
                
                debug_log(logging,l_frame_number,false,true,false,'CCR/CCA\nafter')

            else
                -- if packet is cc-request
                --      get imsi
                local l_diam_request = tostring(diam_request())
                
                debug_log(logging,l_frame_number,false,true,false,'CCR/CCA\nbefore')
                
                if  l_diam_request  == '1' then 
                    local l_diam_imsi = {diam_imsi()}
                    for i,l in pairs(l_diam_imsi) do
                        
                        --debug_log(logging,l_frame_number,false,false,false,'packet imsi: ' .. l)

                        if tostring(l) == l_imsi then
                            call_diam_session_id[l_diam_app] = tostring(diam_session_id())
                            packet_list[l_frame_number] = {}
                            packet_list[l_frame_number]['imsi'] = l_imsi
                        end
                    end
                end


            end
        -- 274 - ASR/ASA - abort session
        -- 258 - RAR/RAA - re-auth
        -- 275 - STR/STA - session termination
        elseif (l_diam_cmd == '274') or (l_diam_cmd == '258') or (l_diam_cmd =='275') then
         -- if session-id is already known
            if call_diam_session_id['4'] or call_diam_session_id['16777238'] then
                
                local l_diam_session_id = tostring(diam_session_id())
                
                if (l_diam_session_id == call_diam_session_id['4']) or 
                    (l_diam_session_id == call_diam_session_id['16777238']) then
                    packet_list[l_frame_number] = {}
                    packet_list[l_frame_number]['imsi'] = l_imsi
                end
            end
        end
        debug_log(logging,l_frame_number,false,true,false,'CMD:'.. l_diam_cmd ..'\nafter')
    end
    
    -- this function fills the packet_list table with frames number of relevant gtp messages 
    local function imsi_find_gtp_packets(l_imsi)
        --[[
        GTP codes:
        -- 0x10 = 16 - Create PDP Request
        -- 0x11 = 17 - Create PDP Response
        -- 0x12 = 18 - Update PDP Request
        -- 0x13 = 19 - Update PDP Response
        -- 0x14 = 20 - Delete PDP Response
        -- 0x15 = 21 - Delete PDP Response
        --]]
     
        local l_gtp_type  = tostring(gtp_type())
        local l_frame_number        = tostring(frame_number())
        local logging = false
        
        -- 0x10 = 16 - Create PDP Request
        if l_gtp_type == '16' then
            
            local l_gtp_imsi         = tostring(gtp_imsi())
            local l_gtp_seq_number   = tostring(gtp_seq_number())
            local l_gtp_teid_cp      = tostring(gtp_teid_cp())
           
            debug_log(logging,l_frame_number,true,false,false,'GTP Create Req\nbefore')

            --[[
            if imsi is correct
                - remember sequence number
                - remember sgsn teid from control plane teid 
                - create new packet record
                - create new call record
            --]]
            if l_gtp_imsi == l_imsi then
                seq_number = l_gtp_seq_number
                sgsn_teid = l_gtp_teid_cp 
                packet_list[l_frame_number] = {}
                packet_list[l_frame_number]['imsi'] = l_imsi
            end

            debug_log(logging,l_frame_number,true,false,false,'GTP Create Req\nafter')

        -- 0x11 = 17 - Create PDP Response
        elseif l_gtp_type == '17' then
            local l_gtp_teid         = tostring(gtp_teid())
            local l_gtp_seq_number   = tostring(gtp_seq_number())
            
            debug_log(logging,l_frame_number,true,false,false,'GTP Create Res\nbefore') 

            --[[
            if seq_number and TEID is the same as in Create PDP
                - remember GW teid
                - remember Charging ID 
                - create a new packet record
                - update call record
            --]]
            if (l_gtp_seq_number == seq_number) and (l_gtp_teid == sgsn_teid) then
                --[[
                if gtp cause is "128 Request accepted" or 
                                "129 New PDP type due to network preference" or
                                "130 New PDP type due to single address bearer only"
                    mark get TEID CP and Charging ID
                --]]
                local l_gtp_cause = tostring(gtp_cause())
                if l_gtp_cause == '128' or l_gtp_cause == '129' or l_gtp_cause == '130' then
                    gw_teid      = tostring(gtp_teid_cp())
                    charging_id  = tostring(gtp_charging_id())
                end
                
                packet_list[l_frame_number] = {}
                packet_list[l_frame_number]['imsi'] = l_imsi
            end 
            

            debug_log(logging,l_frame_number,true,false,false,'GTP Create Res\nafter') 

        -- 0x12 = 18 - Update PDP Request
        elseif l_gtp_type == '18'  then
            local l_gtp_teid         = tostring(gtp_teid())
            local l_gtp_teid_cp      = tostring(gtp_teid_cp())
           
            debug_log(logging,l_frame_number,true,false,false,'GTP Update Req\nbefore') 

            --[[
            if to gw_teid
                - create a new packet record
                - update sgsn teid just in case 
            if to sgsn_teid from gw_teid
                - create a new packet record
            --]]
            if (l_gtp_teid == gw_teid) then
                packet_list[l_frame_number] = {}
                packet_list[l_frame_number]['imsi'] = l_imsi
                sgsn_teid = l_gtp_teid_cp
                call_list[call_number]['sgsn_teid'] = sgsn_teid
            elseif (l_gtp_teid == sgsn_teid) and (l_gtp_teid_cp == gw_teid) then
                packet_list[l_frame_number] = {}
                packet_list[l_frame_number]['imsi'] = l_imsi
            end
            
            debug_log(logging,l_frame_number,true,false,false,'GTP Update Req\nafter') 
            

        -- 0x13 = 19 - Update PDP Response
        elseif l_gtp_type == '19' then
            local l_gtp_teid         = tostring(gtp_teid())
            local l_gtp_teid_cp      = tostring(gtp_teid_cp())

            debug_log(logging,l_frame_number,true,false,false,'GTP Update Res\nbefore') 


            --[[
            if from gw_teid to sgsn or from sgsn to gw
                - create a new packet record
            --]]
            if (l_gtp_teid_cp == gw_teid) and (l_gtp_teid == sgsn_teid) or 
                (l_gtp_teid == sgsn_teid) and (l_gtp_teid_cp == gw_teid)  then
                packet_list[l_frame_number] = {}
                packet_list[l_frame_number]['imsi'] = l_imsi
            end  
            
            debug_log(logging,l_frame_number,true,false,false,'GTP Update Res\nafter') 


        -- 0x14 = 20 - Delete PDP Response
        -- 0x15 = 21 - Delete PDP Response
        elseif (l_gtp_type == '20') or (l_gtp_type == '21') then
            local l_gtp_teid         = tostring(gtp_teid())


            debug_log(logging,l_frame_number,true,false,false,'GTP Delete\nbefore') 

            --[[
            if to gw_teid or to sgsn_teid
                - create a new packet record
            --]]
            if (l_gtp_teid == gw_teid) or (l_gtp_teid == sgsn_teid) then
                packet_list[l_frame_number] = {}
                packet_list[l_frame_number]['imsi'] = l_imsi
            end 
            
            debug_log(logging,l_frame_number,true,false,false,'GTP Delete\nafter') 

        end
    end

    
    -- create a function to "postdissect" each frame 
    function pdp_proto.dissector(buffer,pinfo,tree)
        -- obtain the current values the protocol fields
        local l_frame_number        = tostring(frame_number())
        local l_ip_proto            = tostring (ip_proto())
        -- debug_log(true,l_frame_number,false,false,false,'IP:' .. l_ip_proto) 
        -- udp
        if l_ip_proto == '17' then
            
            local l_udp_port = {udp_port()}
            --[[
            if any of udp ports is 2123 use gtp
            --]]
            for i, port in pairs(l_udp_port) do
                if tostring(port) == const_gtp_port then
                    original_gtp_dissector:call(buffer,pinfo,tree)
                    imsi_find_gtp_packets(imsi)
                elseif tostring(port) == const_rad_auth_port then
                    original_rad_auth_dissector:call(buffer,pinfo,tree)
                    imsi_find_radius_packets(imsi)
                elseif tostring(port) == const_rad_acct_port then
                    original_rad_acct_dissector:call(buffer,pinfo,tree)
                    imsi_find_radius_packets(imsi)
                end
            end

        -- tcp
        elseif l_ip_proto == '6' then
            -- debug_log(true,l_frame_number,false,false,false,'TRYING TO GET TCP') 
            original_diam_dissector:call(buffer,pinfo,tree)
            imsi_find_diam_packets(imsi)
        end

        --[[
        if packet is in the list mark it with corresponding fields 
        --]]
        if packet_list[l_frame_number] then
            local subtree = tree:add(pdp_proto,"PDP Finder Data")
            subtree:add(imsi_field,packet_list[l_frame_number]['imsi'])
        end

    end
    
    local function dialog_menu(buffer,pinfo,tree)
        local function dialog_func(l_imsi,c_gtp_port,c_rad_auth_port,c_rad_acct_port,c_rad_delay,c_diam_gx_port,c_diam_gy_port)
            imsi = 0
            -- setting defaults
            if c_gtp_port ~= '' then
                const_gtp_port = c_gtp_port
            else
                const_gtp_port = '2123'
            end
            
            if c_rad_auth_port ~= '' then
                const_rad_auth_port = c_rad_auth_port
            else
                const_rad_auth_port = '1812'
            end
            
            if c_rad_acct_port ~= '' then
                const_rad_acct_port = c_rad_acct_port
            else
                const_rad_acct_port = '1813'
            end
            
            if c_rad_delay ~= '' then
                const_rad_delay = c_rad_delay
            else
                const_rad_delay = '15'
            end
            
            if c_diam_gx_port ~= '' then
                const_diam_gx_port = c_diam_gx_port
            else
                const_daim_gx_port = '3868'
            end
 
            if c_diam_gy_port ~= '' then
                const_diam_gy_port = c_diam_gy_port
            else
                const_daim_gy_port = '3868'
            end




            packet_list = {}
            imsi = l_imsi
            seq_number = 0
            sgsn_teid = 0
            gw_teid = 0
            charging_id = 0
            call_diam_session_id['16777238'] = false
            call_diam_session_id['4'] = false
            rad_message = {}
            if first_run then

                io.output('pdp_finder.log')
                local udp_dissector_table = DissectorTable.get("udp.port")
                original_gtp_dissector = udp_dissector_table:get_dissector('2123')
                udp_dissector_table:add(const_gtp_port,pdp_proto)
                
                original_rad_auth_dissector = udp_dissector_table:get_dissector('1812')
                original_rad_acct_dissector = udp_dissector_table:get_dissector('1813')
                
                udp_dissector_table:add(const_rad_auth_port,pdp_proto)
                udp_dissector_table:add(const_rad_acct_port,pdp_proto)
                
                local tcp_dissector_table = DissectorTable.get("tcp.port")
                original_diam_dissector = tcp_dissector_table:get_dissector("3868")

                tcp_dissector_table:add(const_diam_gx_port,pdp_proto)
                tcp_dissector_table:add(const_diam_gy_port,pdp_proto)
                
                first_run = false
            end
            set_filter('pdp.imsi=='..imsi)
            apply_filter()
        end
    
        new_dialog("Find calls for IMSI:", dialog_func,"IMSI", "GTP port (=2123)", "RADIUS Auth port (=1812)", "RADIUS Acct port (=1813)","RADIUS response delay (=15)", "DIAMETER Gx Port (=3868)", "DIAMETER Gy Port (=3868)")
    end

    
    register_menu("PDP Finder",dialog_menu,MENU_TOOLS_UNSORTED)
end
