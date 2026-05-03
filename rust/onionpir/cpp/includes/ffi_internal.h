#pragma once
// Internal definitions shared between ffi.cpp and ffi_c.cpp.
// Not part of the public API.

#include "server.h"
#include "client.h"
#include "pir.h"
#include "shared_key_store.h"

#include <sstream>
#include <cstring>
#include <stdexcept>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <atomic>
#include <unordered_map>

#include "ffi.h"  // for QueryStatus, PirParamsInfo, and free function declarations

// ======================== Opaque wrapper definitions ========================

class OnionPirServer {
public:
  PirParams params;
  PirServer inner;

  explicit OnionPirServer(size_t num_entries) : params(num_entries), inner(params) {}
};

class OnionPirClient {
public:
  PirParams params;
  PirClient inner;

  explicit OnionPirClient(size_t num_entries) : params(num_entries), inner(params) {}
  OnionPirClient(size_t num_entries, size_t client_id, const seal::SecretKey &sk)
      : params(num_entries), inner(params, client_id, sk) {}
};

// ======================== Async query queue ========================

struct QueuedQuery {
  uint64_t ticket;
  uint64_t client_id;
  std::vector<uint8_t> query_bytes;
};

struct QueryResult {
  QueryStatus status;
  std::vector<uint8_t> data;
  std::string error;
};

class OnionPirQueryQueue {
public:
  OnionPirServer &server;
  std::atomic<uint64_t> next_ticket{1};

  std::mutex mu;
  std::condition_variable cv;
  bool stopped = false;

  std::deque<QueuedQuery> pending;
  uint64_t processing_ticket = 0;
  std::unordered_map<uint64_t, QueryResult> results;

  std::thread worker;

  explicit OnionPirQueryQueue(OnionPirServer &srv);
  ~OnionPirQueryQueue();

private:
  void run();
};
