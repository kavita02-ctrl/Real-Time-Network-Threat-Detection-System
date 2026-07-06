#include "threatdetector/FeatureConfig.hpp"

#include <cstdlib>
#include <fstream>
#include <stdexcept>

namespace threatdetector {
namespace {

std::string read_file(const std::string& path) {
  std::ifstream input(path);
  if (!input) {
    throw std::runtime_error("failed to open feature config: " + path);
  }
  return std::string((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
}

std::size_t find_key(const std::string& text, const std::string& key) {
  const std::string quoted = "\"" + key + "\"";
  const auto pos = text.find(quoted);
  if (pos == std::string::npos) {
    throw std::runtime_error("feature config missing key: " + key);
  }
  return pos;
}

std::vector<std::string> parse_string_array(const std::string& text, const std::string& key) {
  const auto key_pos = find_key(text, key);
  const auto start = text.find('[', key_pos);
  const auto end = text.find(']', start);
  if (start == std::string::npos || end == std::string::npos) {
    throw std::runtime_error("invalid string array for key: " + key);
  }

  std::vector<std::string> result;
  auto cursor = start + 1;
  while (cursor < end) {
    const auto quote1 = text.find('"', cursor);
    if (quote1 == std::string::npos || quote1 >= end) {
      break;
    }
    const auto quote2 = text.find('"', quote1 + 1);
    if (quote2 == std::string::npos || quote2 > end) {
      throw std::runtime_error("unterminated string in key: " + key);
    }
    result.push_back(text.substr(quote1 + 1, quote2 - quote1 - 1));
    cursor = quote2 + 1;
  }
  return result;
}

std::vector<float> parse_number_array(const std::string& text, const std::string& key) {
  const auto key_pos = find_key(text, key);
  const auto start = text.find('[', key_pos);
  const auto end = text.find(']', start);
  if (start == std::string::npos || end == std::string::npos) {
    throw std::runtime_error("invalid number array for key: " + key);
  }

  std::vector<float> result;
  auto cursor = start + 1;
  while (cursor < end) {
    while (cursor < end && (text[cursor] == ' ' || text[cursor] == '\n' ||
                            text[cursor] == '\t' || text[cursor] == ',')) {
      ++cursor;
    }
    if (cursor >= end) {
      break;
    }
    const char* begin = text.data() + cursor;
    char* parse_end = nullptr;
    const float value = std::strtof(begin, &parse_end);
    if (parse_end == begin) {
      throw std::runtime_error("invalid number in key: " + key);
    }
    result.push_back(value);
    cursor = static_cast<std::size_t>(parse_end - text.data());
  }
  return result;
}

float parse_number(const std::string& text, const std::string& key) {
  const auto key_pos = find_key(text, key);
  const auto colon = text.find(':', key_pos);
  if (colon == std::string::npos) {
    throw std::runtime_error("invalid numeric key: " + key);
  }
  const char* begin = text.data() + colon + 1;
  char* parse_end = nullptr;
  const float value = std::strtof(begin, &parse_end);
  if (parse_end == begin) {
    throw std::runtime_error("invalid number for key: " + key);
  }
  return value;
}

}  // namespace

FeatureConfig FeatureConfig::load(const std::string& path) {
  const auto text = read_file(path);
  FeatureConfig config;
  config.feature_order_ = parse_string_array(text, "feature_order");
  config.mean_ = parse_number_array(text, "mean");
  config.std_ = parse_number_array(text, "std");
  config.threshold_ = parse_number(text, "threshold");

  if (config.feature_order_.empty()) {
    throw std::runtime_error("feature config contains no features");
  }
  if (config.mean_.size() != config.feature_order_.size() ||
      config.std_.size() != config.feature_order_.size()) {
    throw std::runtime_error("feature config mean/std sizes do not match feature_order");
  }
  return config;
}

void FeatureConfig::normalize(std::vector<float>& features) const {
  if (features.size() != feature_order_.size()) {
    throw std::runtime_error("feature vector size does not match feature config");
  }

  for (std::size_t i = 0; i < features.size(); ++i) {
    const float denom = std_[i] == 0.0F ? 1.0F : std_[i];
    features[i] = (features[i] - mean_[i]) / denom;
  }
}

}  // namespace threatdetector
