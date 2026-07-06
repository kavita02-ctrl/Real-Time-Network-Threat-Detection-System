#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace threatdetector {

class FeatureConfig {
 public:
  static FeatureConfig load(const std::string& path);

  void normalize(std::vector<float>& features) const;
  std::size_t feature_count() const { return feature_order_.size(); }
  float threshold() const { return threshold_; }
  const std::vector<std::string>& feature_order() const { return feature_order_; }

 private:
  std::vector<std::string> feature_order_;
  std::vector<float> mean_;
  std::vector<float> std_;
  float threshold_{0.0F};
};

}  // namespace threatdetector
