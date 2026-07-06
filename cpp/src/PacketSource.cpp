#include "threatdetector/PacketSource.hpp"

#include <chrono>
#include <cstdint>
#include <random>

#ifdef THREATDETECTOR_HAS_PCAP
#include <pcap/pcap.h>
#endif

namespace threatdetector {

namespace {

std::uint16_t read_be16(const unsigned char* data) {
  return static_cast<std::uint16_t>((data[0] << 8) | data[1]);
}

std::uint32_t read_be32(const unsigned char* data) {
  return (static_cast<std::uint32_t>(data[0]) << 24) |
         (static_cast<std::uint32_t>(data[1]) << 16) |
         (static_cast<std::uint32_t>(data[2]) << 8) |
         static_cast<std::uint32_t>(data[3]);
}

std::uint64_t now_ns(std::uint64_t offset) {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  return static_cast<std::uint64_t>(
             std::chrono::duration_cast<std::chrono::nanoseconds>(now).count()) +
         offset;
}

}  // namespace

std::string ip_to_string(std::uint32_t ip) {
  return std::to_string((ip >> 24) & 0xff) + "." + std::to_string((ip >> 16) & 0xff) +
         "." + std::to_string((ip >> 8) & 0xff) + "." + std::to_string(ip & 0xff);
}

void run_synthetic_source(std::size_t packet_count, const PacketHandler& handler) {
  std::mt19937 rng(42);
  std::uniform_int_distribution<int> host(2, 250);
  std::uniform_int_distribution<int> len(64, 1500);
  std::bernoulli_distribution tcp(0.8);
  std::bernoulli_distribution suspicious(0.015);

  const std::uint32_t subnet = (10U << 24) | (1U << 16);
  for (std::size_t i = 0; i < packet_count; ++i) {
    const bool burst = suspicious(rng);
    PacketEvent event;
    event.timestamp_ns = now_ns(i * 1000);
    event.src_ip = subnet | (static_cast<std::uint32_t>(host(rng)) << 8) |
                   static_cast<std::uint32_t>(host(rng));
    event.dst_ip = subnet | (static_cast<std::uint32_t>(host(rng)) << 8) |
                   static_cast<std::uint32_t>(host(rng));
    event.src_port = static_cast<std::uint16_t>(1024 + (i % 50000));
    event.dst_port = static_cast<std::uint16_t>(burst ? 22 : 443);
    event.protocol = tcp(rng) ? 6 : 17;
    event.length = static_cast<std::uint32_t>(burst ? 1500 : len(rng));
    event.syn = event.protocol == 6 && (i % 9 == 0 || burst);
    event.fin = event.protocol == 6 && i % 31 == 0;
    event.rst = event.protocol == 6 && burst;
    handler(event);
  }
}

#ifdef THREATDETECTOR_HAS_PCAP

namespace {

bool parse_packet(const pcap_pkthdr* header, const unsigned char* bytes, PacketEvent& event) {
  if (header->caplen < 14) {
    return false;
  }

  const std::uint16_t ether_type = read_be16(bytes + 12);
  if (ether_type != 0x0800) {
    return false;
  }

  const unsigned char* ip = bytes + 14;
  const std::size_t ip_available = header->caplen - 14;
  if (ip_available < 20) {
    return false;
  }

  const std::uint8_t version = ip[0] >> 4;
  const std::uint8_t ihl = (ip[0] & 0x0f) * 4;
  if (version != 4 || ihl < 20 || ip_available < ihl) {
    return false;
  }

  const std::uint8_t protocol = ip[9];
  if (protocol != 6 && protocol != 17) {
    return false;
  }

  const unsigned char* transport = ip + ihl;
  const std::size_t transport_available = ip_available - ihl;
  if (transport_available < 4) {
    return false;
  }

  event.timestamp_ns =
      static_cast<std::uint64_t>(header->ts.tv_sec) * 1'000'000'000ULL +
      static_cast<std::uint64_t>(header->ts.tv_usec) * 1000ULL;
  event.protocol = protocol;
  event.length = header->len;
  event.src_ip = read_be32(ip + 12);
  event.dst_ip = read_be32(ip + 16);
  event.src_port = read_be16(transport);
  event.dst_port = read_be16(transport + 2);

  if (protocol == 6 && transport_available >= 14) {
    const std::uint8_t flags = transport[13];
    event.fin = (flags & 0x01) != 0;
    event.syn = (flags & 0x02) != 0;
    event.rst = (flags & 0x04) != 0;
  }

  return true;
}

bool consume_pcap(pcap_t* handle, const PacketHandler& handler, std::string& error) {
  pcap_pkthdr* header = nullptr;
  const unsigned char* bytes = nullptr;
  while (true) {
    const int rc = pcap_next_ex(handle, &header, &bytes);
    if (rc == 1) {
      PacketEvent event;
      if (parse_packet(header, bytes, event)) {
        handler(event);
      }
    } else if (rc == 0) {
      continue;
    } else if (rc == -2) {
      return true;
    } else {
      error = pcap_geterr(handle);
      return false;
    }
  }
}

}  // namespace

bool replay_pcap_file(const std::string& path, const PacketHandler& handler, std::string& error) {
  char errbuf[PCAP_ERRBUF_SIZE]{};
  pcap_t* handle = pcap_open_offline(path.c_str(), errbuf);
  if (!handle) {
    error = errbuf;
    return false;
  }
  const bool ok = consume_pcap(handle, handler, error);
  pcap_close(handle);
  return ok;
}

bool capture_interface(const std::string& name, const PacketHandler& handler, std::string& error) {
  char errbuf[PCAP_ERRBUF_SIZE]{};
  pcap_t* handle = pcap_open_live(name.c_str(), 65535, 1, 10, errbuf);
  if (!handle) {
    error = errbuf;
    return false;
  }
  pcap_setnonblock(handle, 0, errbuf);
  const bool ok = consume_pcap(handle, handler, error);
  pcap_close(handle);
  return ok;
}

#endif

}  // namespace threatdetector
