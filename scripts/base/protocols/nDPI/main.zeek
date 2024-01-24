@load base/init-bare
module NDPI;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
		## Timestamp for when the event happened.
        ts: time             &log;
		## The connection's 4-tuple of endpoint addresses/ports.
        id: conn_id          &log;
		## The transport layer protocol of the connection.
        l4_proto: transport_proto &log;
        ## 
        proto: string        &log &optional;
        ## The application level protocol.
        app_proto: string    &log &optional;
        ## Category of application protocol 
        category: string     &log &optional;
        ## Number of packet that nDPI has analyzed to find the protocol
        num_packet_analyzed: count     &log &optional;
        ## Indicates if the connection is encripted.
        encripted: string    &log &optional;
        ## Name of the host server 
        host_server: string  &log &optional;
        ## Identifier of the risk type of the connection
        risk_type: string    &log &optional;
        ## Risck score of the connection calculated by nDPI
        risk_score: count    &log &optional;
    };
}

redef record connection += {
    ndpi: Info &optional;
};

event ndpi_done(c: connection, info: ndpi_info) 
    {
    if ( ! c?$ndpi )
        {
        local p = get_port_transport_proto(c$id$resp_p);
        c$ndpi = Info($ts=network_time(), $id=c$id, $l4_proto=p);
        }

    if ( info?$proto )
        c$ndpi$proto=info$proto;
    if ( info?$app_proto )
        c$ndpi$app_proto=info$app_proto;
    if ( info?$category )
        c$ndpi$category=info$category;
    if ( info?$num_packet_analyzed ) 
        c$ndpi$num_packet_analyzed=info$num_packet_analyzed;
    if ( info?$encripted )
        {
        if (info$encripted == 1)
            c$ndpi$encripted="YES";
        else   
            c$ndpi$encripted="NO";
        }
    if ( info?$host_server_name )
        c$ndpi$host_server=info$host_server_name;
    
    if ( info?$risk_type )
        c$ndpi$risk_type=info$risk_type;
    if ( info?$risk_score )
        c$ndpi$risk_score=info$risk_score;


    }

event zeek_init() &priority=5
    {
    Log::create_stream(NDPI::LOG, [$columns=Info, $path="ndpi"]);
    }

event connection_state_remove(c: connection)
    {
    if ( c?$ndpi )
        Log::write(NDPI::LOG, c$ndpi);
    }