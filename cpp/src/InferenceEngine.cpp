#include "threatdetector/InferenceEngine.hpp"

#include <chrono>
#include <iostream>
#include <stdexcept>
#include <utility>

#include "threatdetector/OnnxModel.hpp"

namespace threatdetector {

InferenceEngine::InferenceEngine(EngineOptions options)
    : options_(std::move(options)),
      config_(FeatureConfig::load(options_.config_path)),
      queue_(options_.queue_capacity) {
  if (options_.workers == 0) {
    throw std::runtime_error("worker count must be greater than zero");
  }
  if (options_.batch_size == 0) {
    throw std::runtime_error("batch size must be greater than zero");
  }
}

InferenceEngine::~InferenceEngine() {
  stop();
}

void InferenceEngine::start() {
  bool expected = false;
  if (!running_.compare_exchange_strong(expected, true)) {
    return;
  }
  workers_.reserve(options_.workers);
  for (std::size_t i = 0; i < options_.workers; ++i) {
    workers_.emplace_back([this, i] { worker_loop(i); });
  }
}

bool InferenceEngine::submit(PacketEvent packet) {
  if (!running_) {
    return false;
  }
  ++submitted_;
  if (!queue_.try_push(std::move(packet))) {
    ++dropped_;
    return false;
  }
  return true;
}

void InferenceEngine::stop() {
  bool expected = true;
  if (!running_.compare_exchange_strong(expected, false)) {
    return;
  }
  queue_.close();
  for (auto& worker : workers_) {
    if (worker.joinable()) {
      worker.join();
    }
  }
  workers_.clear();
}

EngineStats InferenceEngine::stats() const {
  return EngineStats{
      submitted_.load(),
      processed_.load(),
      alerts_.load(),
      dropped_.load(),
  };
}

void InferenceEngine::worker_loop(std::size_t worker_id) {
  OnnxModel model(options_.model_path, config_.feature_count());
  std::vector<PacketEvent> events;
  std::vector<float> batch;
  events.reserve(options_.batch_size);
  batch.reserve(options_.batch_size * config_.feature_count());

  while (true) {
    PacketEvent packet;
    if (!queue_.wait_pop(packet, std::chrono::milliseconds(100))) {
      if (queue_.closed()) {
        break;
      }
      continue;
    }

    events.clear();
    batch.clear();
    events.push_back(packet);

    PacketEvent drained;
    while (events.size() < options_.batch_size && queue_.try_pop(drained)) {
      events.push_back(drained);
    }

    for (const auto& event : events) {
      auto features = extractor_.extract(event);
      config_.normalize(features);
      batch.insert(batch.end(), features.begin(), features.end());
    }

    const auto scores = model.predict(batch, events.size());
    processed_.fetch_add(static_cast<std::uint64_t>(scores.size()));
    for (std::size_t i = 0; i < scores.size(); ++i) {
      if (scores[i] > config_.threshold()) {
        ++alerts_;
        std::cerr << "alert worker=" << worker_id << " score=" << scores[i]
                  << " threshold=" << config_.threshold()
                  << " src=" << ip_to_string(events[i].src_ip)
                  << " dst=" << ip_to_string(events[i].dst_ip)
                  << " proto=" << static_cast<int>(events[i].protocol) << '\n';
      }
    }
  }
}

}  // namespace threatdetector
