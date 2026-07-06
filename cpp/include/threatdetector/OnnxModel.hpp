#pragma once

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include <onnxruntime_cxx_api.h>

namespace threatdetector {

class OnnxModel {
 public:
  OnnxModel(const std::string& model_path, std::size_t feature_count);

  std::vector<float> predict(const std::vector<float>& batch, std::size_t rows);

 private:
  std::size_t feature_count_;
  Ort::Env env_;
  Ort::SessionOptions session_options_;
  std::unique_ptr<Ort::Session> session_;
  Ort::MemoryInfo memory_info_;
  std::string input_name_;
  std::string output_name_;
};

}  // namespace threatdetector
