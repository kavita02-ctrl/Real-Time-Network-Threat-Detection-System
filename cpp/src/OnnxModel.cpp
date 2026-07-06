#include "threatdetector/OnnxModel.hpp"

#include <array>
#include <stdexcept>

namespace threatdetector {

OnnxModel::OnnxModel(const std::string& model_path, std::size_t feature_count)
    : feature_count_(feature_count),
      env_(ORT_LOGGING_LEVEL_WARNING, "threat_detector"),
      session_(nullptr),
      memory_info_(Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault)) {
  session_options_.SetIntraOpNumThreads(1);
  session_options_.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);
  session_ = std::make_unique<Ort::Session>(env_, model_path.c_str(), session_options_);

  Ort::AllocatorWithDefaultOptions allocator;
  auto input_name = session_->GetInputNameAllocated(0, allocator);
  auto output_name = session_->GetOutputNameAllocated(0, allocator);
  input_name_ = input_name.get();
  output_name_ = output_name.get();
}

std::vector<float> OnnxModel::predict(const std::vector<float>& batch, std::size_t rows) {
  if (rows == 0) {
    return {};
  }
  if (batch.size() != rows * feature_count_) {
    throw std::runtime_error("ONNX input batch has unexpected size");
  }

  std::array<int64_t, 2> shape{
      static_cast<int64_t>(rows),
      static_cast<int64_t>(feature_count_),
  };

  auto input = Ort::Value::CreateTensor<float>(
      memory_info_,
      const_cast<float*>(batch.data()),
      batch.size(),
      shape.data(),
      shape.size());

  const char* input_names[] = {input_name_.c_str()};
  const char* output_names[] = {output_name_.c_str()};
  auto outputs = session_->Run(
      Ort::RunOptions{nullptr}, input_names, &input, 1, output_names, 1);

  auto& output = outputs.front();
  const auto count = output.GetTensorTypeAndShapeInfo().GetElementCount();
  const float* values = output.GetTensorData<float>();
  return std::vector<float>(values, values + count);
}

}  // namespace threatdetector
