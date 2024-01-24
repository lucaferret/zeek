// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Conn.h"

#include "zeek/zeek-config.h"

#include <binpac.h>
#include <cctype>

#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/NetVar.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/Timer.h"
#include "zeek/TunnelEncapsulation.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/pia/PIA.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"
#include "zeek/packet_analysis/protocol/tcp/TCP.h"
#include "zeek/session/Manager.h"

namespace zeek {

uint64_t Connection::total_connections = 0;
uint64_t Connection::current_connections = 0;

Connection::Connection(const detail::ConnKey& k, double t, const ConnTuple* id, uint32_t flow, const Packet* pkt)
    : Session(t, connection_timeout, connection_status_update, detail::connection_status_update_interval), key(k) {
    orig_addr = id->src_addr;
    resp_addr = id->dst_addr;
    orig_port = id->src_port;
    resp_port = id->dst_port;
    proto = TRANSPORT_UNKNOWN;
    orig_flow_label = flow;
    resp_flow_label = 0;
    saw_first_orig_packet = 1;
    saw_first_resp_packet = 0;

    if ( pkt->l2_src )
        memcpy(orig_l2_addr, pkt->l2_src, sizeof(orig_l2_addr));
    else
        memset(orig_l2_addr, 0, sizeof(orig_l2_addr));

    if ( pkt->l2_dst )
        memcpy(resp_l2_addr, pkt->l2_dst, sizeof(resp_l2_addr));
    else
        memset(resp_l2_addr, 0, sizeof(resp_l2_addr));

    vlan = pkt->vlan;
    inner_vlan = pkt->inner_vlan;

    weird = 0;

    suppress_event = 0;

    finished = 0;

    adapter = nullptr;
    primary_PIA = nullptr;

    ++current_connections;
    ++total_connections;

    encapsulation = pkt->encap;

#ifdef NDPI_LIB
    zeek::analyzer::Analyzer* ndpi_mgr = analyzer_mgr->InstantiateAnalyzer("NDPI", this);
    ndpi_analyzer = dynamic_cast<zeek::analyzer::nDPI::NDPIAnalyzer*>(ndpi_mgr);
    
	nDPI_flow = (struct ndpi_flow_struct *)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
	if (nDPI_flow == NULL) 
        reporter->FatalError("Not enough memory for nDPI flow struct");
	memset(nDPI_flow, 0, SIZEOF_FLOW_STRUCT);
    l7_protocol;
    nDPI_packet_processed = 0;
    end_detection = 0;
#endif
}

Connection::~Connection() {
    if ( ! finished )
        reporter->InternalError("Done() not called before destruction of Connection");

    CancelTimers();

    if ( conn_val )
        conn_val->SetOrigin(nullptr);

    delete adapter;

    --current_connections;

#ifdef NDPI_LIB
    ndpi_flow_free(nDPI_flow);
    ndpi_analyzer->Done();
    delete ndpi_analyzer;
#endif
}

void Connection::CheckEncapsulation(const std::shared_ptr<EncapsulationStack>& arg_encap) {
    if ( encapsulation && arg_encap ) {
        if ( *encapsulation != *arg_encap ) {
            if ( tunnel_changed && (zeek::detail::tunnel_max_changes_per_connection == 0 ||
                                    tunnel_changes < zeek::detail::tunnel_max_changes_per_connection) ) {
                tunnel_changes++;
                EnqueueEvent(tunnel_changed, nullptr, GetVal(), arg_encap->ToVal());
            }

            encapsulation = std::make_shared<EncapsulationStack>(*arg_encap);
        }
    }

    else if ( encapsulation ) {
        if ( tunnel_changed ) {
            EncapsulationStack empty;
            EnqueueEvent(tunnel_changed, nullptr, GetVal(), empty.ToVal());
        }

        encapsulation = nullptr;
    }

    else if ( arg_encap ) {
        if ( tunnel_changed )
            EnqueueEvent(tunnel_changed, nullptr, GetVal(), arg_encap->ToVal());

        encapsulation = std::make_shared<EncapsulationStack>(*arg_encap);
    }
}

void Connection::Done() {
    finished = 1;

    if ( adapter ) {
        if ( ConnTransport() == TRANSPORT_TCP ) {
            auto* ta = static_cast<packet_analysis::TCP::TCPSessionAdapter*>(adapter);
            assert(ta->IsAnalyzer("TCP"));
            analyzer::tcp::TCP_Endpoint* to = ta->Orig();
            analyzer::tcp::TCP_Endpoint* tr = ta->Resp();

            packet_analysis::TCP::TCPAnalyzer::GetStats().StateLeft(to->state, tr->state);
        }

        if ( ! adapter->IsFinished() )
            adapter->Done();
    }

#ifdef NDPI_LIB
    if ( l7_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN )
        NdpiInformation();
    ndpi_analyzer->NDPIHandler(conn_val);
#endif
}

void Connection::NextPacket(double t, bool is_orig, const IP_Hdr* ip, int len, int caplen, const u_char*& data,
                            int& record_packet, int& record_content,
                            // arguments for reproducing packets
                            const Packet* pkt) {
    run_state::current_timestamp = t;
    run_state::current_pkt = pkt;

    if ( adapter ) {
        if ( adapter->Skipping() )
            return;

        record_current_packet = record_packet;
        record_current_content = record_content;
        adapter->NextPacket(len, data, is_orig, -1, ip, caplen);
        record_packet = record_current_packet;
        record_content = record_current_content;
    }
    else
        last_time = t;

    run_state::current_timestamp = 0;
    run_state::current_pkt = nullptr;
}

bool Connection::IsReuse(double t, const u_char* pkt) { return adapter && adapter->IsReuse(t, pkt); }

namespace {
// Flip everything that needs to be flipped in the connection
// record that is known on this level. This needs to align
// with GetVal() and connection's layout in init-bare.
void flip_conn_val(const RecordValPtr& conn_val) {
    // Flip the the conn_id (c$id).
    const auto& id_val = conn_val->GetField<zeek::RecordVal>(0);
    const auto& tmp_addr = id_val->GetField<zeek::AddrVal>(0);
    const auto& tmp_port = id_val->GetField<zeek::PortVal>(1);
    id_val->Assign(0, id_val->GetField<zeek::AddrVal>(2));
    id_val->Assign(1, id_val->GetField<zeek::PortVal>(3));
    id_val->Assign(2, tmp_addr);
    id_val->Assign(3, tmp_port);

    // Flip the endpoints within connection.
    const auto& tmp_endp = conn_val->GetField<zeek::RecordVal>(1);
    conn_val->Assign(1, conn_val->GetField(2));
    conn_val->Assign(2, tmp_endp);
}
} // namespace

const RecordValPtr& Connection::GetVal() {
    if ( ! conn_val ) {
        conn_val = make_intrusive<RecordVal>(id::connection);

        TransportProto prot_type = ConnTransport();

        auto id_val = make_intrusive<RecordVal>(id::conn_id);
        id_val->Assign(0, make_intrusive<AddrVal>(orig_addr));
        id_val->Assign(1, val_mgr->Port(ntohs(orig_port), prot_type));
        id_val->Assign(2, make_intrusive<AddrVal>(resp_addr));
        id_val->Assign(3, val_mgr->Port(ntohs(resp_port), prot_type));

        auto orig_endp = make_intrusive<RecordVal>(id::endpoint);
        orig_endp->Assign(0, 0);
        orig_endp->Assign(1, 0);
        orig_endp->Assign(4, orig_flow_label);

        const int l2_len = sizeof(orig_l2_addr);
        char null[l2_len]{};

        if ( memcmp(&orig_l2_addr, &null, l2_len) != 0 )
            orig_endp->Assign(5, fmt_mac(orig_l2_addr, l2_len));

        auto resp_endp = make_intrusive<RecordVal>(id::endpoint);
        resp_endp->Assign(0, 0);
        resp_endp->Assign(1, 0);
        resp_endp->Assign(4, resp_flow_label);

        if ( memcmp(&resp_l2_addr, &null, l2_len) != 0 )
            resp_endp->Assign(5, fmt_mac(resp_l2_addr, l2_len));

        conn_val->Assign(0, std::move(id_val));
        conn_val->Assign(1, std::move(orig_endp));
        conn_val->Assign(2, std::move(resp_endp));
        // 3 and 4 are set below.
        conn_val->Assign(5, make_intrusive<TableVal>(id::string_set)); // service
        conn_val->Assign(6, val_mgr->EmptyString());                   // history

        if ( ! uid )
            uid.Set(zeek::detail::bits_per_uid);

        conn_val->Assign(7, uid.Base62("C"));

        if ( encapsulation && encapsulation->Depth() > 0 )
            conn_val->Assign(8, encapsulation->ToVal());

        if ( vlan != 0 )
            conn_val->Assign(9, vlan);

        if ( inner_vlan != 0 )
            conn_val->Assign(10, inner_vlan);
    }

    if ( adapter )
        adapter->UpdateConnVal(conn_val.get());

    conn_val->AssignTime(3, start_time); // ###
    conn_val->AssignInterval(4, last_time - start_time);

    if ( ! history.empty() ) {
        auto v = conn_val->GetFieldAs<StringVal>(6);
        if ( *v != history )
            conn_val->Assign(6, history);
    }

    conn_val->SetOrigin(this);

    return conn_val;
}

analyzer::Analyzer* Connection::FindAnalyzer(analyzer::ID id) { return adapter ? adapter->FindChild(id) : nullptr; }

analyzer::Analyzer* Connection::FindAnalyzer(const zeek::Tag& tag) {
    return adapter ? adapter->FindChild(tag) : nullptr;
}

analyzer::Analyzer* Connection::FindAnalyzer(const char* name) { return adapter->FindChild(name); }

void Connection::AppendAddl(const char* str) {
    const auto& cv = GetVal();

    const char* old = cv->GetFieldAs<StringVal>(6)->CheckString();
    const char* format = *old ? "%s %s" : "%s%s";

    cv->Assign(6, util::fmt(format, old, str));
}

void Connection::Match(detail::Rule::PatternType type, const u_char* data, int len, bool is_orig, bool bol, bool eol,
                       bool clear_state) {
    if ( primary_PIA )
        primary_PIA->Match(type, data, len, is_orig, bol, eol, clear_state);
}

void Connection::RemovalEvent() {
    if ( connection_state_remove )
        EnqueueEvent(connection_state_remove, nullptr, GetVal());
}

void Connection::Weird(const char* name, const char* addl, const char* source) {
    weird = 1;
    reporter->Weird(this, name, addl ? addl : "", source ? source : "");
}

void Connection::FlipRoles() {
    IPAddr tmp_addr = resp_addr;
    resp_addr = orig_addr;
    orig_addr = tmp_addr;

    uint32_t tmp_port = resp_port;
    resp_port = orig_port;
    orig_port = tmp_port;

    const int l2_len = sizeof(orig_l2_addr);
    u_char tmp_l2_addr[l2_len];
    memcpy(tmp_l2_addr, resp_l2_addr, l2_len);
    memcpy(resp_l2_addr, orig_l2_addr, l2_len);
    memcpy(orig_l2_addr, tmp_l2_addr, l2_len);

    bool tmp_bool = saw_first_resp_packet;
    saw_first_resp_packet = saw_first_orig_packet;
    saw_first_orig_packet = tmp_bool;

    uint32_t tmp_flow = resp_flow_label;
    resp_flow_label = orig_flow_label;
    orig_flow_label = tmp_flow;

    if ( conn_val )
        flip_conn_val(conn_val);

    if ( adapter )
        adapter->FlipRoles();

    analyzer_mgr->ApplyScheduledAnalyzers(this);

    AddHistory('^');

    if ( connection_flipped )
        EnqueueEvent(connection_flipped, nullptr, GetVal());
}

void Connection::Describe(ODesc* d) const {
    session::Session::Describe(d);

    switch ( proto ) {
        case TRANSPORT_TCP: d->Add("TCP"); break;

        case TRANSPORT_UDP: d->Add("UDP"); break;

        case TRANSPORT_ICMP: d->Add("ICMP"); break;

        case TRANSPORT_UNKNOWN:
            d->Add("unknown");
            reporter->InternalWarning("unknown transport in Connection::Describe()");

            break;

        default: reporter->InternalError("unhandled transport type in Connection::Describe");
    }

    d->SP();
    d->Add(orig_addr);
    d->Add(":");
    d->Add(ntohs(orig_port));

    d->SP();
    d->AddSP("->");

    d->Add(resp_addr);
    d->Add(":");
    d->Add(ntohs(resp_port));

    d->NL();
}

void Connection::IDString(ODesc* d) const {
    d->Add(orig_addr);
    d->AddRaw(":", 1);
    d->Add(ntohs(orig_port));
    d->AddRaw(" > ", 3);
    d->Add(resp_addr);
    d->AddRaw(":", 1);
    d->Add(ntohs(resp_port));
}

void Connection::SetSessionAdapter(packet_analysis::IP::SessionAdapter* aa, analyzer::pia::PIA* pia) {
    adapter = aa;
    primary_PIA = pia;
}

void Connection::CheckFlowLabel(bool is_orig, uint32_t flow_label) {
    uint32_t& my_flow_label = is_orig ? orig_flow_label : resp_flow_label;

    if ( my_flow_label != flow_label ) {
        if ( conn_val ) {
            RecordVal* endp = conn_val->GetFieldAs<RecordVal>(is_orig ? 1 : 2);
            endp->Assign(4, flow_label);
        }

        if ( connection_flow_label_changed && (is_orig ? saw_first_orig_packet : saw_first_resp_packet) ) {
            EnqueueEvent(connection_flow_label_changed, nullptr, GetVal(), val_mgr->Bool(is_orig),
                         val_mgr->Count(my_flow_label), val_mgr->Count(flow_label));
        }

        my_flow_label = flow_label;
    }

    if ( is_orig )
        saw_first_orig_packet = 1;
    else
        saw_first_resp_packet = 1;
}

bool Connection::PermitWeird(const char* name, uint64_t threshold, uint64_t rate, double duration) {
    return detail::PermitWeird(weird_state, name, threshold, rate, duration);
}

#ifdef NDPI_LIB
void Connection::NdpiAnalyzePacket(Packet* pkt) {
    const struct ndpi_iphdr* ip;
    const struct ndpi_ipv6hdr* ip6;
    const struct ndpi_ethhdr* ethernet;
    u_int64_t time_ms;
    uint16_t ip_size;
    const u_int16_t eth_offset = 0;
    u_int16_t ip_offset;
    uint16_t type;
	uint8_t protocol_was_guessed = 0;
    time_ms = ((u_int64_t)pkt->ts.tv_sec) * 1000 + pkt->ts.tv_usec / 1000;
    // clear bit if risk type was of unidirectional traffic at previous iteration
    if ( ! pkt->is_orig  ) 
        nDPI_flow->risk &= ~(1ULL << NDPI_UNIDIRECTIONAL_TRAFFIC);
    ++nDPI_packet_processed;
	switch (pkt->link_type) {
		case DLT_NULL:
			if (ntohl(*((uint32_t *)&pkt->data[eth_offset])) == 0x00000002) {
			  	type = ETH_P_IP;
				} 
                else {
			  	type = ETH_P_IPV6;
				}
			ip_offset = 4 + eth_offset;
			break;
		case DLT_EN10MB:
			ethernet = (struct ndpi_ethhdr*) &pkt->data[eth_offset];
			ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
			type = pkt->eth_type;
			break;
		default:
			Weird("Non IP/Ethernet packet");
			return;
	}
	
    if (type == ETH_P_IP) {
        ip = (struct ndpi_iphdr *)&pkt->data[ip_offset];
        ip6 = nullptr;
    } else if (type == ETH_P_IPV6) {
        ip = nullptr;
        ip6 = (struct ndpi_ipv6hdr *)&pkt->data[ip_offset];
    }

    ip_size = pkt->len - ip_offset;
    if ( ! end_detection ) {
        u_int enough_packets = ( ((proto == TRANSPORT_UDP) && nDPI_packet_processed > MAX_PACKET_UDP) || ((proto == TRANSPORT_TCP) && nDPI_packet_processed > MAX_PACKET_TCP)) ? 1 : 0;

        struct ndpi_flow_input_info input_info;

        memset(&input_info, '\0', sizeof(input_info));

        input_info.in_pkt_dir = NDPI_IN_PKT_DIR_UNKNOWN;
        input_info.seen_flow_beginning = NDPI_FLOW_BEGINNING_UNKNOWN;

        l7_protocol = ndpi_detection_process_packet(session_mgr->ndpi_struct, nDPI_flow,
                    ip != nullptr ? (uint8_t *)ip : (uint8_t *)ip6,
                    ip_size, time_ms, &input_info);

        enough_packets |= nDPI_flow->fail_with_unknown;
        if ( enough_packets || (l7_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN ) ) {
            if ( ( ! enough_packets ) && ndpi_extra_dissection_possible(session_mgr->ndpi_struct, nDPI_flow))
                ;
            else {
                end_detection = 1;
                if ( l7_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN ) {
                    u_int8_t proto_guessed;
                    
                    l7_protocol = ndpi_detection_giveup(session_mgr->ndpi_struct, nDPI_flow, 1, &proto_guessed);
                }
            }
        }
    }
}

void Connection::NdpiInformation() {
    const char* name_server = ndpi_get_flow_info(nDPI_flow, &l7_protocol);
    if ( ndpi_analyzer ) {
        if ( l7_protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN ) {
            ndpi_analyzer->InsertValue(0, ndpi_get_proto_name(session_mgr->ndpi_struct, l7_protocol.master_protocol));
        }
        if ( l7_protocol.category != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED ) {
            ndpi_analyzer->InsertValue(2, ndpi_category_get_name(session_mgr->ndpi_struct, l7_protocol.category));
        }
        ndpi_analyzer->InsertValue(1, ndpi_get_proto_name(session_mgr->ndpi_struct, l7_protocol.app_protocol));
        ndpi_analyzer->InsertValue(3, nDPI_packet_processed);
        ndpi_analyzer->InsertValue(4, ndpi_is_encrypted_proto(session_mgr->ndpi_struct, l7_protocol));
        if ( name_server )
            ndpi_analyzer->InsertValue(5, name_server);
    }
    /*
    if ( l7_protocol.master_protocol == NDPI_PROTOCOL_HTTP ) {
        if ( nDPI_flow->http.user_agent[0] != '\0' && nDPI_flow->http.detected_os[0] != '\0' )
            fprintf(stderr, "user agent %s and OS %s\n", nDPI_flow->http.user_agent, nDPI_flow->http.detected_os);
    }
    if ( l7_protocol.master_protocol == NDPI_PROTOCOL_HTTP ) {
        if(nDPI_flow->http.url[0] != '\0') {
            ndpi_risk_enum risk= ndpi_validate_url(nDPI_flow->http.url);
            if ( risk != NDPI_NO_RISK )
                fprintf(stderr, "risk type %s\n", ndpi_risk2str(risk));
        }
    }
    */
    if ( nDPI_flow->risk ) {
        u_int16_t cli_score, srv_score;

        ndpi_analyzer->InsertValue(6, ndpi_risk2str(nDPI_flow->risk_infos->id));
        ndpi_analyzer->InsertValue(7, ndpi_risk2score(nDPI_flow->risk, &cli_score, &srv_score));
    }
    
    }
#endif

} // namespace zeek
