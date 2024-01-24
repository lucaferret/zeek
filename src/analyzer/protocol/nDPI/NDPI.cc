#include "zeek/analyzer/protocol/nDPI/events.bif.h"
#include "zeek/analyzer/protocol/nDPI/types.bif.h"
#include "zeek/analyzer/protocol/nDPI/NDPI.h"

namespace zeek::analyzer::nDPI {

NDPIAnalyzer::NDPIAnalyzer(Connection* conn) : Analyzer("NDPI", conn) {
    ndpi_val = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::NDPI::ndpi_info);
}

NDPIAnalyzer::~NDPIAnalyzer() {
    if ( ndpi_val )
        ndpi_val->SetOrigin(nullptr);
}

void NDPIAnalyzer::Done() { Analyzer::Done(); }

void NDPIAnalyzer::InsertValue(int index, const char* val) {
    ndpi_val->Assign(index, val);
}

void NDPIAnalyzer::InsertValue(int index, int val) {
    ndpi_val->Assign(index, val);
}

void NDPIAnalyzer::NDPIHandler(RecordValPtr conn_val) {
    EventHandlerPtr f = event_registry->Register("ndpi_done", true);
    if ( f ) {
        EnqueueConnEvent(f, conn_val, ndpi_val);
    }
}

}