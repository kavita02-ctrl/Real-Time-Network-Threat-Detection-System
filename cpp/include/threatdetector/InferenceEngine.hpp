#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include "threatdetector/BoundedQueue.hpp"
#include "threatdetector/FeatureConfig.hpp"
#include "threatdetector/FeatureExtractor.hpp"
#include "threatdetector/Packet.hpp"

namespace threatdetector {

struct EngineOptions {
  std::string model_path;
  std::string config_path;
  std::size_t workers{4};
  std::size_t queue_capacity{65536};
  std::size_t batch_size{32};
};

struct EngineStats {
  std::uint64_t submitted{0};
  std::uint64_t processed{0};
  std::uint64_t alerts{0};
  std::uint64_t dropped{0};
};

class InferenceEngine {
 public:
  explicit InferenceEngine(EngineOptions options);
  ~InferenceEngine();

  void start();
  bool submit(PacketEvent packet);
  void stop();
  EngineStats stats() const;

 private:
  void worker_loop(std::size_t worker_id);

  EngineOptions options_;
  FeatureConfig config_;
  FeatureExtractor extractor_;
  BoundedQueue<PacketEvent> queue_;
  std::vector<std::thread> workers_;
  std::atomic<bool> running_{false};
  std::atomic<std::uint64_t> submitted_{0};
  std::atomic<std::uint64_t> processed_{0};
  std::atomic<std::uint64_t> alerts_{0};
  std::atomic<std::uint64_t> dropped_{0};
};

}  // namespace threatdetector
