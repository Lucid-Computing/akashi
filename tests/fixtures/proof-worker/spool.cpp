// Drive the CPU spool implementation from the pinned FlashProve checkout.
#include "prover/spool.h"

int main(int argc, char **argv) {
  Spool spool;
  if (argc != 3 || !spool.open(argv[1], 1024, 202048)) return 1;
  std::vector<Spool::Request> jobs;
  if (spool.take(jobs, 1) != 1) return 2;
  const auto &id = jobs.front().id;
  const uint32_t y = 0;
  const std::string bytes = "private fixture";
  if (std::string(argv[2]) == "candidate") {
    if (!spool.stage_answer(id, {{"y", &y, sizeof y}, {"proof", bytes.data(), bytes.size()}})) return 3;
  } else if (std::string(argv[2]) == "failed") {
    if (!spool.stage_failed(id)) return 4;
  } else return 5;
  return spool.release(Spool::now_ms()) && spool.settled(-1) ? 0 : 6;
}
