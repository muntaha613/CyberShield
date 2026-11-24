// CyberShield V3 - C++17 concurrent firewall-simulation engine (Abeeha: engine & OS features)
//
// OS concepts demonstrated
//   * Producer-consumer: a producer thread fills a bounded queue, worker threads consume it.
//   * Synchronisation : one mutex guards the queue + counters + rules; two condition variables
//                       (cv = "not empty", cvSpace = "not full") block threads with no busy-waiting.
//   * Threads         : std::thread (a thin wrapper over POSIX pthreads on Linux, built with -pthread).
//   * Thread pools    : FIXED pool (always N workers) vs ADAPTIVE pool (grows/shrinks with queue load).
//   * Semaphores      : a counting semaphore (mutex + condvar, since std::counting_semaphore is C++20) acts as a
//                       token bucket. A limiter thread releases tokens at RATE packets/s; each worker must
//                       acquire() one token before inspecting a packet. This is semaphore-based rate control.
//   * Priority packets: a second, high-priority queue. Workers drain it first, with an aging rule (after
//                       PRIO_BURST consecutive priority packets one normal packet is served) so normal
//                       traffic is never starved.
//
// Protocol: line commands on stdin, one JSON object per line on stdout.
//   V2 commands (unchanged): GENERATE n | STATS | RULES | ADD ip port proto action | DELETE id | TOGGLE id | QUIT
//   New commands           : WORKERS | MODE FIXED|ADAPTIVE | SETWORKERS n | DELAY us | BENCH n [delay_us]
//                            RATE pps (0 = unlimited) | PRIORITY n (inject n high-priority packets)
//   The "stats" event keeps every V2 field and only ADDS fields, so the existing GUI keeps working.
#include <iostream>
#include <string>
#include <vector>
#include <deque>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <random>
#include <sstream>
#include <chrono>
#include <algorithm>
#include <cstdio>
using namespace std;
using Clock = chrono::steady_clock;

struct Packet { int id, port; string ip, protocol; bool bench = false; int prio = 0; Clock::time_point t{}; };  // prio: 0 normal, 1 high
struct Rule { int id, port; string ip, protocol, action; bool enabled; };
struct WorkerStat { atomic<long> processed{0}; atomic<bool> busy{false}, alive{false}; };

enum class Mode { FIXED, ADAPTIVE };
const char* modeName(Mode m) { return m == Mode::FIXED ? "FIXED" : "ADAPTIVE"; }

constexpr int MAX_WORKERS = 8, FIXED_WORKERS = 4, MIN_WORKERS = 2;
constexpr size_t capacity = 3000;            // bounded queue size (unchanged from V2)
constexpr size_t PRIO_CAP = 500;             // bounded size of the high-priority queue
constexpr int PRIO_BURST = 8;                // aging: after 8 priority packets in a row, serve one normal packet

mutex mu, outmu;                             // mu: queue/rules/counters, outmu: stdout
condition_variable cv, cvSpace;              // cv: queue not empty, cvSpace: queue not full
deque<Packet> queuePackets;                  // normal-priority queue (bounded by `capacity`)
deque<Packet> queuePriority;                 // high-priority queue (bounded by PRIO_CAP)
int highStreak = 0;                          // consecutive priority pops (guarded by mu)
long long waitSumUs[2] = {0, 0}, waitCnt[2] = {0, 0}, procPrio = 0;   // queue-wait stats [0]=normal [1]=priority (guarded by mu)
mt19937 rng(random_device{}());              // packet generator RNG (guarded by mu)
size_t qtotal() { return queuePackets.size() + queuePriority.size(); }   // call with mu held
bool qempty() { return queuePackets.empty() && queuePriority.empty(); }  // call with mu held
vector<Rule> rules;
atomic<bool> running{true};
int nextId = 1, nextRule = 1, generated = 0, processed = 0, allowed = 0, denied = 0;  // guarded by mu
size_t peakQueue = 0;                                                                   // guarded by mu
atomic<int> activeWorkers{0};                // live worker threads
atomic<int> busyWorkers{0};                  // workers currently handling a packet
atomic<int> peakWorkers{0};
atomic<int> targetWorkers{0};                // desired pool size (slot >= target must exit)
atomic<Mode> mode{Mode::FIXED};
atomic<int> delayUs{0};                      // simulated per-packet inspection cost
atomic<int> benchDone{0};

WorkerStat wstats[MAX_WORKERS];
thread pool[MAX_WORKERS];
mutex poolmu;                                // serialises spawning/joining of pool threads

// ---------- counting semaphore (token bucket) ----------
// Classic counting semaphore built from a mutex + condition variable. acquire() = P/wait, release() = V/signal.
// When `bypass` is set (rate limiting off, or shutting down) acquire() returns immediately.
struct Semaphore {
    mutex m; condition_variable c; long count = 0; bool bypass = true; int waiting = 0;
    void acquire() {
        unique_lock<mutex> lk(m);
        if (!bypass && count <= 0) { waiting++; c.wait(lk, [&] { return bypass || count > 0; }); waiting--; }
        if (!bypass) count--;
    }
    void release(long n, long cap) {                      // V(n), never letting the bucket exceed `cap` (burst size)
        { lock_guard<mutex> lk(m); count = min(cap, count + n); }
        c.notify_all();
    }
    void setBypass(bool b) { { lock_guard<mutex> lk(m); bypass = b; count = 0; } c.notify_all(); }
    int waiters() { lock_guard<mutex> lk(m); return waiting; }
};
Semaphore limiter;
atomic<int> rateLimit{0};                    // packets per second; 0 = unlimited
atomic<bool> limiterStop{false};
void setRate(int r) { rateLimit = r; limiter.setBypass(r <= 0); }

// Refills the bucket at rateLimit tokens/second (measured with a real clock so sleep jitter does not skew the rate).
void limiterThread() {
    double acc = 0; auto last = Clock::now();
    while (!limiterStop) {
        this_thread::sleep_for(chrono::milliseconds(5));
        auto now = Clock::now(); double dt = chrono::duration<double>(now - last).count(); last = now;
        int r = rateLimit.load();
        if (r <= 0) { acc = 0; continue; }
        acc += r * dt;
        long whole = (long)acc; acc -= whole;
        if (whole > 0) limiter.release(whole, max(1, r / 10));     // burst = 100 ms worth of tokens
    }
}

// ---------- output helpers ----------
string esc(const string &s) { string o; for (char c : s) { if (c == '"' || c == '\\') o += '\\'; if (c == '\n') o += "\\n"; else if (c != '\r') o += c; } return o; }
void emit(const string &s) { lock_guard<mutex> l(outmu); cout << s << endl; }
string packetJson(const Packet &p, const string &decision, int rule) {
    return "{\"type\":\"packet\",\"id\":" + to_string(p.id) + ",\"ip\":\"" + esc(p.ip) + "\",\"port\":" + to_string(p.port) +
           ",\"protocol\":\"" + p.protocol + "\",\"decision\":\"" + decision + "\",\"rule\":" + to_string(rule) + ",\"priority\":\"" + (p.prio ? "HIGH" : "NORMAL") + "\"}";
}
string pct(size_t q) { char b[32]; snprintf(b, sizeof b, "%.1f", 100.0 * q / capacity); return b; }

// ---------- consumer ----------
void worker(int slot) {
    WorkerStat &ws = wstats[slot];
    while (true) {
        Packet p;
        long long queueWaitUs = 0;
        {
            unique_lock<mutex> lk(mu);
            cv.wait(lk, [&] { return !running || slot >= targetWorkers.load() || !qempty(); });
            if (slot >= targetWorkers.load()) break;
            if (qempty()) break;

            // Prioritize HIGH packets, but serve a NORMAL after eight HIGHs if available.
            if (!queuePriority.empty() && (queuePackets.empty() || highStreak < PRIO_BURST)) {
                p = move(queuePriority.front()); queuePriority.pop_front(); highStreak++;
            } else {
                p = move(queuePackets.front()); queuePackets.pop_front(); highStreak = 0;
            }
            queueWaitUs = chrono::duration_cast<chrono::microseconds>(Clock::now() - p.t).count();
            ws.busy = true;
            busyWorkers++;
        }
        cvSpace.notify_one();

        // IMPORTANT: acquire the semaphore BEFORE firewall inspection or accounting.
        // While rate-limited, packets may be dequeued and busy, but are NOT processed.
        // Benchmark packets do not consume tokens.
        if (!p.bench) limiter.acquire();
        int d = delayUs.load();
        if (d > 0) this_thread::sleep_for(chrono::microseconds(d));

        string decision = "ALLOW";
        int matched = 0;
        {
            // Evaluate shared rules and update counters as a single synchronized operation.
            // The counters represent inspections that actually completed, not pending tokens.
            lock_guard<mutex> lk(mu);
            for (const auto &r : rules) {
                if (r.enabled && (r.ip == "*" || r.ip == p.ip) &&
                    (r.port == 0 || r.port == p.port) &&
                    (r.protocol == "ANY" || r.protocol == p.protocol)) {
                    decision = r.action;
                    matched = r.id;
                    break;
                }
            }
            if (!p.bench) {
                processed++;
                if (decision == "DENY") denied++; else allowed++;
                if (p.prio) procPrio++;
                waitSumUs[p.prio] += queueWaitUs;
                waitCnt[p.prio]++;
            }
        }
        if (p.bench) benchDone++;
        else emit(packetJson(p, decision, matched));
        ws.processed++;
        ws.busy = false;
        busyWorkers--;
    }
    ws.alive = false;
    activeWorkers--;
}

// Resize the pool to t workers (1..MAX_WORKERS). Spawns or retires+joins threads.
void setTarget(int t) {
    t = clamp(t, 1, MAX_WORKERS);
    lock_guard<mutex> pl(poolmu);
    int old = targetWorkers.load();
    if (t == old) return;
    { lock_guard<mutex> lk(mu); targetWorkers = t; }     // change under mu so no waiter misses the wake-up
    if (t > old) {
        for (int i = old; i < t; i++) {
            if (pool[i].joinable()) pool[i].join();
            activeWorkers++; wstats[i].alive = true;
            pool[i] = thread(worker, i);
        }
        int a = activeWorkers.load(), pk = peakWorkers.load();
        while (a > pk && !peakWorkers.compare_exchange_weak(pk, a)) {}
    } else {
        cv.notify_all();
        for (int i = t; i < MAX_WORKERS; i++) if (pool[i].joinable()) pool[i].join();
    }
}

// ---------- adaptive scaler ----------
atomic<bool> scalerStop{false};
void scaler() {
    int idleTicks = 0;
    while (!scalerStop) {
        this_thread::sleep_for(chrono::milliseconds(50));
        if (mode != Mode::ADAPTIVE) { idleTicks = 0; continue; }
        size_t q; { lock_guard<mutex> lk(mu); q = qtotal(); }
        int t = targetWorkers.load();
        if (q >= capacity / 10 && t < MAX_WORKERS) {     // backlog building: add workers
            setTarget(min(MAX_WORKERS, t + 2)); idleTicks = 0;
            emit("{\"type\":\"scale\",\"direction\":\"up\",\"workers\":" + to_string(targetWorkers.load()) + ",\"queued\":" + to_string(q) + "}");
        } else if (q == 0 && busyWorkers.load() < t - 1 && t > MIN_WORKERS) {   // idle: release workers
            if (++idleTicks >= 4) {
                setTarget(t - 1); idleTicks = 0;
                emit("{\"type\":\"scale\",\"direction\":\"down\",\"workers\":" + to_string(targetWorkers.load()) + ",\"queued\":0}");
            }
        } else idleTicks = 0;
    }
}

// ---------- producer ----------
// Build one random packet. Call with mu held (shares the RNG).
Packet randomPacket(int id) {
    static const int ports[] = {22, 53, 80, 443, 8080};
    uniform_int_distribution<int> oct(1, 254), pick(0, 4);
    Packet p{id, ports[pick(rng)], "192.168.1." + to_string(oct(rng)), pick(rng) % 2 ? "TCP" : "UDP"};
    p.t = Clock::now();
    return p;
}

// Pushes `count` random packets, BLOCKING on cvSpace while the bounded queue is full (back-pressure).
void produce(int count, bool bench) {
    unique_lock<mutex> lk(mu);
    for (int i = 0; i < count; i++) {
        if (queuePackets.size() >= capacity) { cv.notify_all(); cvSpace.wait(lk, [] { return queuePackets.size() < capacity || !running; }); }
        Packet p = randomPacket(bench ? 0 : nextId++);
        p.bench = bench;
        queuePackets.push_back(move(p));
        if (!bench) generated++;
        peakQueue = max(peakQueue, queuePackets.size());
        if ((i & 31) == 31) cv.notify_all();             // wake consumers in batches, not per packet
    }
    lk.unlock();
    cv.notify_all();
}

mutex pmu; condition_variable pcv; deque<int> genJobs; bool prodStop = false;
void producer() {
    while (true) {
        int n;
        { unique_lock<mutex> lk(pmu); pcv.wait(lk, [] { return prodStop || !genJobs.empty(); }); if (genJobs.empty()) break; n = genJobs.front(); genJobs.pop_front(); }
        produce(n, false);
    }
}

// ---------- commands ----------
void generate(int count) {
    count = clamp(count, 1, 20000);
    { lock_guard<mutex> lk(pmu); genJobs.push_back(count); }
    pcv.notify_one();
    emit("{\"type\":\"ack\",\"message\":\"Queued " + to_string(count) + " packets\"}");
}
// Inject high-priority packets directly into the priority queue (they overtake everything already waiting).
// The priority queue is bounded (PRIO_CAP), so excess packets are rejected rather than blocking the command loop.
void injectPriority(int count) {
    count = clamp(count, 1, (int)PRIO_CAP);
    int added = 0;
    { lock_guard<mutex> lk(mu);
      while (added < count && queuePriority.size() < PRIO_CAP) {
          Packet p = randomPacket(nextId++); p.prio = 1;
          queuePriority.push_back(move(p)); generated++; added++;
      }
      peakQueue = max(peakQueue, qtotal()); }
    cv.notify_all();
    emit("{\"type\":\"ack\",\"message\":\"Queued " + to_string(added) + " priority packets" + (added < count ? " (priority queue full, " + to_string(count - added) + " rejected)" : "") + "\"}");
}
void stats() {
    string s;
    { lock_guard<mutex> lk(mu);
      s = "{\"type\":\"stats\",\"generated\":" + to_string(generated) + ",\"processed\":" + to_string(processed) + ",\"allowed\":" + to_string(allowed) +
          ",\"denied\":" + to_string(denied) + ",\"queued\":" + to_string(qtotal()) + ",\"workers\":" + to_string(activeWorkers.load()) +
          ",\"busy\":" + to_string(busyWorkers.load()) + ",\"capacity\":" + to_string(capacity) + ",\"utilization\":" + pct(queuePackets.size()) +
          ",\"peak_queue\":" + to_string(peakQueue) + ",\"mode\":\"" + modeName(mode) + "\",\"target_workers\":" + to_string(targetWorkers.load()) +
          ",\"priority_queued\":" + to_string(queuePriority.size()) + ",\"priority_processed\":" + to_string(procPrio) +
          ",\"avg_wait_us_normal\":" + to_string(waitCnt[0] ? waitSumUs[0] / waitCnt[0] : 0) + ",\"avg_wait_us_priority\":" + to_string(waitCnt[1] ? waitSumUs[1] / waitCnt[1] : 0) +
          ",\"rate_limit\":" + to_string(rateLimit.load()) + ",\"rate_waiting\":" + to_string(limiter.waiters()) + "}"; }
    emit(s);
}
void workerReport() {
    string s;
    { lock_guard<mutex> lk(mu);
      s = "{\"type\":\"workers\",\"mode\":\"" + string(modeName(mode)) + "\",\"target\":" + to_string(targetWorkers.load()) + ",\"alive\":" + to_string(activeWorkers.load()) +
          ",\"busy\":" + to_string(busyWorkers.load()) + ",\"queued\":" + to_string(qtotal()) + ",\"capacity\":" + to_string(capacity) +
          ",\"utilization\":" + pct(queuePackets.size()) + ",\"peak_queue\":" + to_string(peakQueue) + ",\"peak_workers\":" + to_string(peakWorkers.load()) + ",\"items\":[";
      bool first = true;
      for (int i = 0; i < MAX_WORKERS; i++) { if (!wstats[i].alive && wstats[i].processed == 0) continue; if (!first) s += ","; first = false;
          s += "{\"id\":" + to_string(i) + ",\"alive\":" + (wstats[i].alive ? "true" : "false") + ",\"busy\":" + (wstats[i].busy ? "true" : "false") + ",\"processed\":" + to_string(wstats[i].processed.load()) + "}"; }
      s += "]}"; }
    emit(s);
}
void listRules() {
    string s;
    { lock_guard<mutex> lk(mu); s = "{\"type\":\"rules\",\"items\":["; bool first = true;
      for (auto &r : rules) { if (!first) s += ","; first = false; s += "{\"id\":" + to_string(r.id) + ",\"ip\":\"" + esc(r.ip) + "\",\"port\":" + to_string(r.port) + ",\"protocol\":\"" + r.protocol + "\",\"action\":\"" + r.action + "\",\"enabled\":" + (r.enabled ? "true" : "false") + "}"; } }
    emit(s + "]}");
}
void waitIdle() { for (int i = 0; i < 4000; i++) { { lock_guard<mutex> lk(mu); if (qempty() && busyWorkers == 0) return; } this_thread::sleep_for(chrono::milliseconds(5)); } }

// Run the same synthetic workload through a FIXED pool and an ADAPTIVE pool and report both.
// Benchmark packets are flagged so they never touch the normal processed/allowed/denied counters.
void benchmark(int count, int delay) {
    count = clamp(count, 1, 50000); delay = clamp(delay, 0, 10000);
    Mode savedMode = mode; int savedTarget = targetWorkers, savedDelay = delayUs;
    waitIdle();
    string res = "{\"type\":\"benchmark\",\"count\":" + to_string(count) + ",\"delay_us\":" + to_string(delay) + ",\"results\":[";
    for (Mode m : {Mode::FIXED, Mode::ADAPTIVE}) {
        mode = m; setTarget(m == Mode::FIXED ? FIXED_WORKERS : MIN_WORKERS); delayUs = delay;
        { lock_guard<mutex> lk(mu); peakQueue = 0; } peakWorkers = activeWorkers.load(); benchDone = 0;
        auto t0 = Clock::now();
        produce(count, true);
        while (benchDone < count) this_thread::sleep_for(chrono::milliseconds(1));
        double sec = chrono::duration<double>(Clock::now() - t0).count();
        size_t pq; { lock_guard<mutex> lk(mu); pq = peakQueue; }
        char b[256]; snprintf(b, sizeof b, "%s{\"mode\":\"%s\",\"seconds\":%.4f,\"throughput\":%.0f,\"peak_queue\":%zu,\"peak_workers\":%d,\"final_workers\":%d}",
                              m == Mode::FIXED ? "" : ",", modeName(m), sec, count / max(sec, 1e-9), pq, peakWorkers.load(), activeWorkers.load());
        res += b;
        waitIdle();
    }
    res += "]}";
    delayUs = savedDelay; mode = savedMode; setTarget(savedTarget);
    { lock_guard<mutex> lk(mu); peakQueue = 0; }
    emit(res);
}

int main() {
    ios::sync_with_stdio(false); cin.tie(nullptr);
    setTarget(FIXED_WORKERS);
    thread prod(producer), scal(scaler), lim(limiterThread);
    emit("{\"type\":\"ready\",\"message\":\"CyberShield C++ engine online\"}");
    string line;
    while (getline(cin, line)) {
        istringstream in(line); string cmd; in >> cmd;
        if (cmd == "GENERATE") { int n; if (!(in >> n)) n = 100; generate(n); }
        else if (cmd == "STATS") stats();
        else if (cmd == "RULES") listRules();
        else if (cmd == "WORKERS") workerReport();
        else if (cmd == "MODE") {
            string m; in >> m; transform(m.begin(), m.end(), m.begin(), ::toupper);
            if (m == "FIXED") { mode = Mode::FIXED; setTarget(FIXED_WORKERS); emit("{\"type\":\"ack\",\"message\":\"Mode FIXED (4 workers)\"}"); }
            else if (m == "ADAPTIVE") { mode = Mode::ADAPTIVE; emit("{\"type\":\"ack\",\"message\":\"Mode ADAPTIVE (2-8 workers)\"}"); }
            else emit("{\"type\":\"error\",\"message\":\"Usage: MODE FIXED|ADAPTIVE\"}");
        }
        else if (cmd == "SETWORKERS") { int n; if (in >> n && n >= 1 && n <= MAX_WORKERS) { mode = Mode::FIXED; setTarget(n); emit("{\"type\":\"ack\",\"message\":\"Workers set to " + to_string(n) + "\"}"); } else emit("{\"type\":\"error\",\"message\":\"Usage: SETWORKERS 1-8\"}"); }
        else if (cmd == "DELAY") { int d; if (in >> d && d >= 0 && d <= 10000) { delayUs = d; emit("{\"type\":\"ack\",\"message\":\"Per-packet delay " + to_string(d) + " us\"}"); } else emit("{\"type\":\"error\",\"message\":\"Usage: DELAY 0-10000\"}"); }
        else if (cmd == "RATE") { int r; if (in >> r && r >= 0 && r <= 100000) { setRate(r); emit("{\"type\":\"ack\",\"message\":\"" + (r ? "Rate limit " + to_string(r) + " packets/s" : string("Rate limit off")) + "\"}"); } else emit("{\"type\":\"error\",\"message\":\"Usage: RATE 0-100000 (0 = unlimited)\"}"); }
        else if (cmd == "PRIORITY") { int n; if (!(in >> n)) n = 10; injectPriority(n); }
        else if (cmd == "BENCH") { int n, d; if (!(in >> n)) n = 5000; if (!(in >> d)) d = 200; benchmark(n, d); }
        else if (cmd == "ADD") {
            string ip, proto, action; int port;
            if (in >> ip >> port >> proto >> action) {
                transform(proto.begin(), proto.end(), proto.begin(), ::toupper); transform(action.begin(), action.end(), action.begin(), ::toupper);
                if (port >= 0 && port <= 65535 && (proto == "TCP" || proto == "UDP" || proto == "ANY") && (action == "ALLOW" || action == "DENY")) {
                    lock_guard<mutex> lk(mu); rules.push_back({nextRule++, port, ip, proto, action, true}); emit("{\"type\":\"ack\",\"message\":\"Rule added\"}");
                } else emit("{\"type\":\"error\",\"message\":\"Invalid rule\"}");
            } else emit("{\"type\":\"error\",\"message\":\"Usage: ADD ip port protocol action\"}");
            listRules();
        }
        else if (cmd == "DELETE") { int id; if (in >> id) { { lock_guard<mutex> lk(mu); rules.erase(remove_if(rules.begin(), rules.end(), [&](const Rule &r) { return r.id == id; }), rules.end()); } listRules(); } }
        else if (cmd == "TOGGLE") { int id; if (in >> id) { { lock_guard<mutex> lk(mu); for (auto &r : rules) if (r.id == id) r.enabled = !r.enabled; } listRules(); } }
        else if (cmd == "QUIT") break;
        else emit("{\"type\":\"error\",\"message\":\"Unknown command\"}");
    }
    // Graceful shutdown: stop scaler, let producer finish queued jobs, then let workers drain the queue.
    setRate(0);                                          // shutdown drains at full speed (release anyone blocked on the semaphore)
    limiterStop = true; lim.join();
    scalerStop = true; scal.join();
    { lock_guard<mutex> lk(pmu); prodStop = true; } pcv.notify_all(); prod.join();
    { lock_guard<mutex> lk(mu); running = false; }
    cv.notify_all();
    { lock_guard<mutex> pl(poolmu); for (auto &t : pool) if (t.joinable()) t.join(); }
    return 0;
}
