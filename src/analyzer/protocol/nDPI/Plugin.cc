// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/nDPI/NDPI.h"

namespace zeek::plugin::detail::Zeek_NDPI {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(new zeek::analyzer::Component("NDPI", zeek::analyzer::nDPI::NDPIAnalyzer::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::NDPI";
        config.description = "NDPI Integration";
        return config;
    }
} plugin;

} // namespace zeek::plugin::detail::Zeek_NDPI
