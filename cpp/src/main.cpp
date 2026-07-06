#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

#include "threatdetector/InferenceEngine.hpp"
#include "threatdetector/PacketSource.hpp"

namespace {

struct Args {
  std::string model;
  std::string config;
  std::string pcap;
  std::string interface;
  std::size_t synthetic{0};
  std::size_t workers{4};
  std::size_t queue_capacity{65536};
  std::size_t batch_size{32};
};

void usage(const char* program) {
  std::cerr << "usage: " << program
            << " --model model.onnx --config feature_config.json"
            << " [--pcap file.pcap | --interface eth0 | --synthetic 100000]"
            << " [--workers 4] [--queue-capacity 65536] [--batch-size 32]\n";
}

bool parse_size(const char* text, std::size_t& value) {
  char* end = nullptr;
  const auto parsed = std::strtoull(text, &end, 10);
  if (end == text || *end != '\0') {
    return false;
  }
  value = static_cast<std::size_t>(parsed);
  return true;
}

bool parse_args(int argc, char** argv, Args& args) {
  for (int i = 1; i < argc; ++i) {
    const std::string flag = argv[i];
    auto need_value = [&](const std::string& name) -> const char* {
      if (i + 1 >= argc) {
        throw std::runtime_error("missing value for " + name);
      }
      return argv[++i];
    };

    if (flag == "--model") {
      args.model = need_value(flag);
    } else if (flag == "--config") {
      args.config = need_value(flag);
    } else if (flag == "--pcap") {
      args.pcap = need_value(flag);
    } else if (flag == "--interface") {
      args.interface = need_value(flag);
    } else if (flag == "--synthetic") {
      if (!parse_size(need_value(flag), args.synthetic)) {
        return false;
      }
    } else if (flag == "--workers") {
      if (!parse_size(need_value(flag), args.workers)) {
        return false;
      }
    } else if (flag == "--queue-capacity") {
      if (!parse_size(need_value(flag), args.queue_capacity)) {
        return false;
      }
    } else if (flag == "--batch-size") {
      if (!parse_size(need_value(flag), args.batch_size)) {
        return false;
      }
    } else if (flag == "--help" || flag == "-h") {
      return false;
    } else {
      throw std::runtime_error("unknown argument: " + flag);
    }
  }

  if (args.model.empty() || args.config.empty()) {
    return false;
  }
  if (args.pcap.empty() && args.interface.empty() && args.synthetic == 0) {
    args.synthetic = 10000;
  }
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    Args args;
    if (!parse_args(argc, argv, args)) {
      usage(argv[0]);
      return 2;
    }

    threatdetector::EngineOptions options;
    options.model_path = args.model;
    options.config_path = args.config;
    options.workers = args.workers;
    options.queue_capacity = args.queue_capacity;
    options.batch_size = args.batch_size;

    threatdetector::InferenceEngine engine(options);
    engine.start();

    auto submit = [&](const threatdetector::PacketEvent& packet) {
      engine.submit(packet);
    };

    bool source_ok = true;
    std::string error;
    if (!args.pcap.empty()) {
#ifdef THREATDETECTOR_HAS_PCAP
      source_ok = threatdetector::replay_pcap_file(args.pcap, submit, error);
#else
      error = "binary was built without libpcap support";
      source_ok = false;
#endif
    } else if (!args.interface.empty()) {
#ifdef THREATDETECTOR_HAS_PCAP
      source_ok = threatdetector::capture_interface(args.interface, submit, error);
#else
      error = "binary was built without libpcap support";
      source_ok = false;
#endif
    } else {
      threatdetector::run_synthetic_source(args.synthetic, submit);
    }

    engine.stop();
    const auto stats = engine.stats();
    std::cout << "submitted=" << stats.submitted << " processed=" << stats.processed
              << " alerts=" << stats.alerts << " dropped=" << stats.dropped << '\n';

    if (!source_ok) {
      std::cerr << "packet source failed: " << error << '\n';
      return 1;
    }
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "fatal: " << ex.what() << '\n';
    return 1;
  }
}
