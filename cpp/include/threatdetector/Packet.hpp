#pragma once

#include <cstdint>
#include <string>

namespace threatdetector {

struct PacketEvent {
  std::uint64_t timestamp_ns{0};
  std::uint32_t src_ip{0};
  std::uint32_t dst_ip{0};
  std::uint16_t src_port{0};
  std::uint16_t dst_port{0};
  std::uint8_t protocol{0};
  std::uint32_t length{0};
  bool syn{false};
  bool fin{false};
  bool rst{false};
};

std::string ip_to_string(std::uint32_t ip);

}  // namespace threatdetector
