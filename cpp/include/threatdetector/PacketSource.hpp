#pragma once

#include <cstddef>
#include <functional>
#include <string>

#include "threatdetector/Packet.hpp"

namespace threatdetector {

using PacketHandler = std::function<void(const PacketEvent&)>;

void run_synthetic_source(std::size_t packet_count, const PacketHandler& handler);

#ifdef THREATDETECTOR_HAS_PCAP
bool replay_pcap_file(const std::string& path, const PacketHandler& handler, std::string& error);
bool capture_interface(const std::string& name, const PacketHandler& handler, std::string& error);
#endif

}  // namespace threatdetector
