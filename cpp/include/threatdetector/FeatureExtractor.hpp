#pragma once

#include <array>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "threatdetector/Packet.hpp"

namespace threatdetector {

class FeatureExtractor {
 public:
  explicit FeatureExtractor(std::uint64_t idle_timeout_ns = 60ULL * 1000ULL * 1000ULL * 1000ULL);

  std::vector<float> extract(const PacketEvent& packet);

 private:
  struct FlowKey {
    std::uint32_t src_ip;
    std::uint32_t dst_ip;
    std::uint16_t src_port;
    std::uint16_t dst_port;
    std::uint8_t protocol;

    bool operator==(const FlowKey& other) const;
  };

  struct FlowKeyHash {
    std::size_t operator()(const FlowKey& key) const;
  };

  struct FlowState {
    std::uint64_t first_seen_ns{0};
    std::uint64_t last_seen_ns{0};
    std::uint64_t packets{0};
    std::uint64_t bytes{0};
    std::uint32_t syn_count{0};
    std::uint32_t fin_count{0};
    std::uint32_t rst_count{0};
  };

  struct Shard {
    std::mutex mutex;
    std::unordered_map<FlowKey, FlowState, FlowKeyHash> flows;
    std::unordered_map<std::uint32_t, std::uint32_t> endpoint_degree;
    std::uint64_t updates{0};
  };

  Shard& shard_for(const FlowKey& key);
  void evict_idle(Shard& shard, std::uint64_t now_ns);

  static constexpr std::size_t kShardCount = 64;
  std::array<Shard, kShardCount> shards_;
  std::uint64_t idle_timeout_ns_;
};

}  // namespace threatdetector
