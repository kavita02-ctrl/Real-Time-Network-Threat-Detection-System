#include "threatdetector/FeatureExtractor.hpp"

#include <algorithm>

namespace threatdetector {

FeatureExtractor::FeatureExtractor(std::uint64_t idle_timeout_ns)
    : idle_timeout_ns_(idle_timeout_ns) {}

bool FeatureExtractor::FlowKey::operator==(const FlowKey& other) const {
  return src_ip == other.src_ip && dst_ip == other.dst_ip && src_port == other.src_port &&
         dst_port == other.dst_port && protocol == other.protocol;
}

std::size_t FeatureExtractor::FlowKeyHash::operator()(const FlowKey& key) const {
  std::size_t seed = key.src_ip;
  seed ^= static_cast<std::size_t>(key.dst_ip) + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
  seed ^= static_cast<std::size_t>(key.src_port) << 16;
  seed ^= static_cast<std::size_t>(key.dst_port);
  seed ^= static_cast<std::size_t>(key.protocol) << 24;
  return seed;
}

std::vector<float> FeatureExtractor::extract(const PacketEvent& packet) {
  const FlowKey key{
      packet.src_ip,
      packet.dst_ip,
      packet.src_port,
      packet.dst_port,
      packet.protocol,
  };

  Shard& shard = shard_for(key);
  std::lock_guard<std::mutex> lock(shard.mutex);

  if (++shard.updates % 4096 == 0) {
    evict_idle(shard, packet.timestamp_ns);
  }

  auto [it, inserted] = shard.flows.try_emplace(key);
  FlowState& state = it->second;
  if (inserted) {
    state.first_seen_ns = packet.timestamp_ns;
    state.last_seen_ns = packet.timestamp_ns;
    ++shard.endpoint_degree[packet.src_ip];
    ++shard.endpoint_degree[packet.dst_ip];
  }

  const std::uint64_t previous_seen = state.last_seen_ns;
  state.last_seen_ns = std::max(state.last_seen_ns, packet.timestamp_ns);
  ++state.packets;
  state.bytes += packet.length;
  state.syn_count += packet.syn ? 1U : 0U;
  state.fin_count += packet.fin ? 1U : 0U;
  state.rst_count += packet.rst ? 1U : 0U;

  const float duration_ms =
      static_cast<float>(state.last_seen_ns - state.first_seen_ns) / 1'000'000.0F;
  const float inter_arrival_ms =
      state.packets <= 1 || packet.timestamp_ns <= previous_seen
          ? 0.0F
          : static_cast<float>(packet.timestamp_ns - previous_seen) / 1'000'000.0F;
  const float mean_packet_len =
      state.packets == 0 ? 0.0F : static_cast<float>(state.bytes) / state.packets;

  return {
      static_cast<float>(state.packets),
      static_cast<float>(state.bytes),
      duration_ms,
      static_cast<float>(shard.endpoint_degree[packet.src_ip]),
      static_cast<float>(shard.endpoint_degree[packet.dst_ip]),
      packet.protocol == 6 ? 1.0F : 0.0F,
      packet.protocol == 17 ? 1.0F : 0.0F,
      mean_packet_len,
      inter_arrival_ms,
      static_cast<float>(state.syn_count),
      static_cast<float>(state.fin_count),
      static_cast<float>(state.rst_count),
  };
}

FeatureExtractor::Shard& FeatureExtractor::shard_for(const FlowKey& key) {
  const auto index = FlowKeyHash{}(key) % shards_.size();
  return shards_[index];
}

void FeatureExtractor::evict_idle(Shard& shard, std::uint64_t now_ns) {
  for (auto it = shard.flows.begin(); it != shard.flows.end();) {
    if (now_ns > it->second.last_seen_ns && now_ns - it->second.last_seen_ns > idle_timeout_ns_) {
      auto dec = [&](std::uint32_t ip) {
        auto degree = shard.endpoint_degree.find(ip);
        if (degree != shard.endpoint_degree.end() && degree->second > 0) {
          --degree->second;
          if (degree->second == 0) {
            shard.endpoint_degree.erase(degree);
          }
        }
      };
      dec(it->first.src_ip);
      dec(it->first.dst_ip);
      it = shard.flows.erase(it);
    } else {
      ++it;
    }
  }
}

}  // namespace threatdetector
