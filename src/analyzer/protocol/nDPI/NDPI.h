
#pragma once

#include <zeek-config.h>
#include "zeek/analyzer/Analyzer.h"

#define MAX_PACKET_UDP 24
#define MAX_PACKET_TCP 80

namespace zeek {

namespace analyzer::nDPI {

class NDPIAnalyzer : public analyzer::Analyzer {

public:
    explicit NDPIAnalyzer(Connection* conn);
    ~NDPIAnalyzer() override;
    void Done() override;

    void InsertValue(int index, const char* val);
    void InsertValue(int index, int val);
    void NDPIHandler(RecordValPtr conn_val);

    static analyzer::Analyzer* Instantiate(Connection* conn) { return new NDPIAnalyzer(conn); }
private:
    RecordValPtr ndpi_val;
};

} // namespace analyzer::nDPI

} // namespace zeek