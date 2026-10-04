#include "../WinMTRNet.h"
#include <process.h>
#include <atomic>
#include <cstdio>
#include <stdexcept>
#include <vector>

[[noreturn]] static void Failed(const char* expression, int line)
{
    std::fprintf(stderr, "FAIL line %d: %s\n", line, expression);
    std::exit(1);
}
#define CHECK(value) do { if (!(value)) Failed(#value, __LINE__); } while (false)

struct Event {
    HANDLE handle;
    explicit Event(bool signaled = false) : handle(CreateEvent(NULL, TRUE, signaled, NULL)) { CHECK(handle); }
    ~Event() { CloseHandle(handle); }
    void Signal() { CHECK(SetEvent(handle)); }
    void Reset() { CHECK(ResetEvent(handle)); }
    void Await() { CHECK(WaitForSingleObject(handle, 3000) == WAIT_OBJECT_0); }
};

template<class Predicate> static void Await(Predicate predicate)
{
    ULONGLONG deadline = GetTickCount64() + 3000;
    while (!predicate()) {
        CHECK(GetTickCount64() < deadline);
        Sleep(1);
    }
}

class FakeBackend : public WinMTRNetBackend {
public:
    typedef unsigned (__stdcall *Entry)(void*);
    std::atomic<Entry> coordinatorEntry{NULL}, probeEntry{NULL};
    std::atomic<HANDLE> coordinatorHandle{NULL}, stopHandle{NULL};
    std::atomic<int> coordinatorLaunches{0}, probeLaunches{0}, dnsLaunches{0};
    std::atomic<int> probes{0}, lookups{0}, destinations{0}, active{0}, shutdowns{0};
    std::atomic<int> packetSize{0}, unsafeShutdowns{0};
    std::atomic<bool> failJoin{false}, failPoll{false}, failInterval{false}, failStopPoll{false};
    bool initializeOK = true, eventOK = true, coordinatorOK = true, destinationOK = true;
    bool dnsOK = true, throwProbe = false;
    int failProbeAt = 0;
    Event destinationEntered, destinationGate{true}, probeEntered, probeGate{true};
    Event dnsEntered, dnsGate{true}, intervalEntered;
    Event joinEntered, joinGate{true};
    std::string capturedDestination;

    bool Initialize(std::string& error) override {
        if (!initializeOK) error = "Injected initialization failure.";
        return initializeOK;
    }
    void Shutdown() override {
        ++shutdowns;
        if (active != 0) ++unsafeShutdowns;
    }
    HANDLE CreateStopEvent() override {
        HANDLE result = eventOK ? WinMTRNetBackend::CreateStopEvent() : NULL;
        stopHandle = result;
        return result;
    }
    HANDLE Launch(Entry entry, void* argument) override {
        Entry expected = NULL;
        coordinatorEntry.compare_exchange_strong(expected, entry);
        if (entry == coordinatorEntry) {
            ++coordinatorLaunches;
            if (!coordinatorOK) return NULL;
            HANDLE result = WinMTRNetBackend::Launch(entry, argument);
            coordinatorHandle = result;
            return result;
        }
        expected = NULL;
        probeEntry.compare_exchange_strong(expected, entry);
        if (entry == probeEntry) {
            int number = ++probeLaunches;
            if (number == failProbeAt) return NULL;
        } else {
            ++dnsLaunches;
            if (!dnsOK) return NULL;
        }
        return WinMTRNetBackend::Launch(entry, argument);
    }
    DWORD Wait(HANDLE handle, DWORD timeout) override {
        if (handle == stopHandle) {
            if (timeout == 0 && failStopPoll.exchange(false)) return WAIT_FAILED;
            if (timeout > 0) {
                intervalEntered.Signal();
                if (failInterval.exchange(false)) return WAIT_FAILED;
            }
        } else {
            if (timeout == INFINITE) {
                joinEntered.Signal();
                CHECK(WaitForSingleObject(joinGate.handle, 3000) == WAIT_OBJECT_0);
                if (failJoin.exchange(false)) return WAIT_FAILED;
            }
            if (handle == coordinatorHandle && timeout == 0 && failPoll.exchange(false)) return WAIT_FAILED;
        }
        return WinMTRNetBackend::Wait(handle, timeout);
    }
    bool ResolveDestination(const std::string& destination, int& address) override {
        ++active;
        ++destinations;
        capturedDestination = destination;
        destinationEntered.Signal();
        CHECK(WaitForSingleObject(destinationGate.handle, 3000) == WAIT_OBJECT_0);
        address = static_cast<int>(htonl(0x7f000001));
        --active;
        return destinationOK;
    }
    std::string ResolveName(int) override {
        ++active;
        ++lookups;
        dnsEntered.Signal();
        CHECK(WaitForSingleObject(dnsGate.handle, 3000) == WAIT_OBJECT_0);
        --active;
        return "late-name";
    }
    ProbeResult Probe(int, void*, WORD size, IPINFO*, void* reply, DWORD) override {
        ++active;
        ++probes;
        packetSize = size;
        probeEntered.Signal();
        CHECK(WaitForSingleObject(probeGate.handle, 3000) == WAIT_OBJECT_0);
        --active;
        if (throwProbe) throw std::runtime_error("Injected probe failure");
        ICMPECHO* echo = static_cast<ICMPECHO*>(reply);
        memset(echo, 0, sizeof(*echo));
        echo->Address = htonl(0x0a000001);
        echo->Status = IP_TTL_EXPIRED_TRANSIT;
        echo->RoundTripTime = 1;
        return ProbeResult{1, ERROR_SUCCESS};
    }
};

static TraceConfig Config(bool dns = false) { return TraceConfig{"example.test", 64, 60, dns}; }
static void Finish(WinMTRNet& net) { Await([&] { return net.TryReap(); }); }

static void ImmediateStopAndRepeat()
{
    FakeBackend backend;
    std::unique_ptr<WinMTRNet> storage(new WinMTRNet(&backend));
    WinMTRNet& net = *storage;
    // Exercise the CRT's worker-thread paths before counting handles; Debug
    // runtime initialization can acquire process-wide handles lazily.
    CHECK(net.StartTrace(Config()));
    backend.intervalEntered.Await();
    net.RequestStop();
    Finish(net);
    DWORD handlesBefore = 0, handlesAfter = 0;
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &handlesBefore));
    for (int i = 0; i < 100; ++i) {
        CHECK(net.StartTrace(Config()));
        net.RequestStop();
        net.RequestStop();
        Finish(net);
        CHECK(net.GetStatus().error.empty());
    }
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &handlesAfter));
    if (handlesAfter != handlesBefore)
        std::fprintf(stderr, "Handle count before=%lu after=%lu\n", handlesBefore, handlesAfter);
    CHECK(handlesAfter == handlesBefore);
    CHECK(backend.dnsLaunches == 0);
}

static void SnapshotAndIntervalCancellation()
{
    FakeBackend backend;
    std::unique_ptr<WinMTRNet> storage(new WinMTRNet(&backend));
    WinMTRNet& net = *storage;
    TraceConfig config = Config();
    CHECK(net.StartTrace(config));
    config.destination = "changed";
    config.packetSize = 4096;
    config.interval = 0;
    config.useDNS = true;
    backend.destinationEntered.Await();
    backend.intervalEntered.Await();
    CHECK(backend.capturedDestination == "example.test");
    CHECK(backend.packetSize == 64);
    CHECK(backend.lookups == 0);
    ULONGLONG started = GetTickCount64();
    net.RequestStop();
    Finish(net);
    CHECK(GetTickCount64() - started < 1000);
}

static void PendingDestination()
{
    FakeBackend backend;
    backend.destinationGate.Reset();
    std::unique_ptr<WinMTRNet> storage(new WinMTRNet(&backend));
    WinMTRNet& net = *storage;
    CHECK(net.StartTrace(Config()));
    backend.destinationEntered.Await();
    net.RequestStop();
    CHECK(!net.TryReap());
    CHECK(!net.StartTrace(Config()));
    CHECK(net.GetStatus().phase == WinMTRNet::Resolving);
    backend.destinationGate.Signal();
    Finish(net);
    CHECK(backend.probeLaunches == 0);
    CHECK(backend.destinations == 1);
}

static void PendingProbes()
{
    FakeBackend backend;
    backend.probeGate.Reset();
    std::unique_ptr<WinMTRNet> storage(new WinMTRNet(&backend));
    WinMTRNet& net = *storage;
    CHECK(net.StartTrace(Config()));
    backend.probeEntered.Await();
    net.RequestStop();
    CHECK(!net.TryReap());
    CHECK(!net.StartTrace(Config()));
    Await([&] { return net.GetStatus().phase == WinMTRNet::DrainingProbes; });
    backend.probeGate.Signal();
    Finish(net);
    CHECK(backend.active == 0);
    CHECK(backend.dnsLaunches == 0);
}

static void PendingDNS()
{
    FakeBackend backend;
    backend.dnsGate.Reset();
    std::unique_ptr<WinMTRNet> storage(new WinMTRNet(&backend));
    WinMTRNet& net = *storage;
    CHECK(net.StartTrace(Config(true)));
    backend.dnsEntered.Await();
    net.RequestStop();
    Await([&] { return net.GetStatus().phase == WinMTRNet::DrainingDNS; });
    CHECK(!net.TryReap());
    CHECK(!net.StartTrace(Config()));
    backend.dnsGate.Signal();
    Finish(net);
    for (int i = 0; i < WinMTRNet::MAX_HOPS; ++i) {
        char name[255];
        net.GetName(i, name);
        CHECK(std::string(name) != "late-name");
    }
    CHECK(backend.lookups > 0);
}

static void ResolutionFailure()
{
    FakeBackend backend;
    backend.destinationOK = false;
    std::unique_ptr<WinMTRNet> storage(new WinMTRNet(&backend));
    WinMTRNet& net = *storage;
    CHECK(net.StartTrace(Config()));
    Finish(net);
    CHECK(net.GetStatus().phase == WinMTRNet::Idle);
    CHECK(net.GetStatus().error == "Unable to resolve destination hostname.");
    CHECK(backend.probeLaunches == 0);
    backend.destinationOK = true;
    CHECK(net.StartTrace(Config()));
    net.RequestStop();
    Finish(net);
    CHECK(net.GetStatus().error.empty());
}

static void InitializationAndEventFailures()
{
    FakeBackend backend;
    backend.initializeOK = false;
    {
        std::unique_ptr<WinMTRNet> storage(new WinMTRNet(&backend));
    WinMTRNet& net = *storage;
        CHECK(!net.StartTrace(Config()));
        CHECK(net.TryReap());
        CHECK(backend.shutdowns == 1);
        CHECK(net.GetStatus().error == "Injected initialization failure.");
    }
    CHECK(backend.shutdowns == 2);
    CHECK(backend.unsafeShutdowns == 0);
    FakeBackend eventBackend;
    eventBackend.eventOK = false;
    std::unique_ptr<WinMTRNet> storage(new WinMTRNet(&eventBackend));
    WinMTRNet& net = *storage;
    CHECK(!net.StartTrace(Config()));
    CHECK(net.TryReap());
    CHECK(net.GetStatus().error == "Unable to create trace stop event.");
    CHECK(eventBackend.coordinatorLaunches == 0);
    eventBackend.eventOK = true;
    CHECK(net.StartTrace(Config()));
    net.RequestStop();
    Finish(net);
}

static void CoordinatorCreationFailure()
{
    FakeBackend backend;
    backend.coordinatorOK = false;
    std::unique_ptr<WinMTRNet> storage(new WinMTRNet(&backend));
    WinMTRNet& net = *storage;
    CHECK(!net.StartTrace(Config()));
    CHECK(net.TryReap());
    CHECK(net.GetStatus().error == "Unable to create trace coordinator.");
    backend.coordinatorOK = true;
    CHECK(net.StartTrace(Config()));
    net.RequestStop();
    Finish(net);
}

static void PartialProbeStartupFailure()
{
    FakeBackend backend;
    backend.probeGate.Reset();
    backend.failProbeAt = 3;
    std::unique_ptr<WinMTRNet> storage(new WinMTRNet(&backend));
    WinMTRNet& net = *storage;
    CHECK(net.StartTrace(Config()));
    Await([&] { return !net.GetStatus().error.empty(); });
    CHECK(net.GetStatus().error == "Unable to create probe worker.");
    backend.probeGate.Signal();
    Finish(net);
    CHECK(backend.probeLaunches == 3);
    CHECK(backend.active == 0);
}

static void DNSCreationFailure()
{
    FakeBackend backend;
    backend.dnsOK = false;
    std::unique_ptr<WinMTRNet> storage(new WinMTRNet(&backend));
    WinMTRNet& net = *storage;
    CHECK(net.StartTrace(Config(true)));
    Finish(net);
    CHECK(backend.dnsLaunches == 1);
    CHECK(net.GetStatus().error == "Unable to create DNS worker.");
    CHECK(backend.lookups == 0);
}

static void ImmediateWorkerFailure()
{
    FakeBackend backend;
    backend.throwProbe = true;
    std::unique_ptr<WinMTRNet> storage(new WinMTRNet(&backend));
    WinMTRNet& net = *storage;
    CHECK(net.StartTrace(Config()));
    Finish(net);
    CHECK(net.GetStatus().error == "Unexpected failure in probe worker.");
    CHECK(backend.active == 0);
}

static void FailedJoinRetainsOwnership()
{
    FakeBackend backend;
    backend.probeGate.Reset();
    backend.joinGate.Reset();
    backend.failJoin = true;
    std::unique_ptr<WinMTRNet> storage(new WinMTRNet(&backend));
    WinMTRNet& net = *storage;
    CHECK(net.StartTrace(Config()));
    backend.probeEntered.Await();
    backend.joinEntered.Await();
    backend.joinGate.Signal();
    Await([&] { return !net.GetStatus().error.empty(); });
    CHECK(net.GetStatus().error == "Unable to wait for trace worker.");
    CHECK(!net.TryReap());
    CHECK(backend.active > 0);
    backend.probeGate.Signal();
    Finish(net);
}

static void FailedCompletionPoll()
{
    FakeBackend backend;
    backend.destinationGate.Reset();
    std::unique_ptr<WinMTRNet> storage(new WinMTRNet(&backend));
    WinMTRNet& net = *storage;
    CHECK(net.StartTrace(Config()));
    backend.destinationEntered.Await();
    backend.failPoll = true;
    CHECK(!net.TryReap());
    CHECK(net.GetStatus().error == "Unable to inspect trace coordinator.");
    CHECK(!net.TryReap());
    backend.destinationGate.Signal();
    Finish(net);
}

static void FailedIntervalWait()
{
    FakeBackend backend;
    backend.failInterval = true;
    std::unique_ptr<WinMTRNet> storage(new WinMTRNet(&backend));
    WinMTRNet& net = *storage;
    CHECK(net.StartTrace(Config()));
    Finish(net);
    CHECK(net.GetStatus().error == "Unable to wait for probe interval.");
}

static void FailedStopPoll()
{
    FakeBackend backend;
    backend.failStopPoll = true;
    std::unique_ptr<WinMTRNet> storage(new WinMTRNet(&backend));
    WinMTRNet& net = *storage;
    CHECK(net.StartTrace(Config()));
    Finish(net);
    CHECK(net.GetStatus().error == "Unable to inspect trace stop event.");
    CHECK(backend.probeLaunches == 0);
}

struct CloseContext { WinMTRNet* net; Event* started; };
static unsigned __stdcall CloseEngine(void* argument)
{
    CloseContext* context = static_cast<CloseContext*>(argument);
    context->started->Signal();
    delete context->net;
    return 0;
}
static void CloseDuringOperation(bool destination, bool dns)
{
    FakeBackend backend;
    if (destination) backend.destinationGate.Reset();
    else if (dns) backend.dnsGate.Reset();
    else backend.probeGate.Reset();
    WinMTRNet* net = new WinMTRNet(&backend);
    CHECK(net->StartTrace(Config(dns)));
    if (destination) backend.destinationEntered.Await();
    else if (dns) backend.dnsEntered.Await();
    else backend.probeEntered.Await();
    Event started;
    CloseContext context{net, &started};
    HANDLE closer = reinterpret_cast<HANDLE>(_beginthreadex(NULL, 0, CloseEngine, &context, 0, NULL));
    CHECK(closer);
    started.Await();
    CHECK(WaitForSingleObject(closer, 20) == WAIT_TIMEOUT);
    CHECK(backend.shutdowns == 0);
    backend.destinationGate.Signal();
    backend.probeGate.Signal();
    backend.dnsGate.Signal();
    CHECK(WaitForSingleObject(closer, 3000) == WAIT_OBJECT_0);
    CHECK(CloseHandle(closer));
    CHECK(backend.shutdowns == 1);
    CHECK(backend.unsafeShutdowns == 0);
}

// Each real worker has its own virtual clock. Scripted probes advance it;
// timed waits advance it without sleeping, then block on cancellation at the end.
class ScriptedBackend : public FakeBackend {
public:
    struct Step { DWORD count, error, status, duration, rtt; };
    std::vector<Step> script;
    std::vector<ULONGLONG> starts[WinMTRNet::MAX_HOPS];
    std::vector<DWORD> delays[WinMTRNet::MAX_HOPS];
    size_t attempts[WinMTRNet::MAX_HOPS] = {};
    Event firstWait, advance{true}, ready;
    ULONGLONG initialClock = 0;
    bool failTimedWait = false;
    static thread_local int hop;
    static thread_local ULONGLONG clock;

    ULONGLONG NowMilliseconds() override {
        if (hop == -1) clock = initialClock;
        return clock;
    }
    ProbeResult Probe(int, void*, WORD, IPINFO* options, void* reply, DWORD) override {
        hop = options->Ttl - 1;
        CHECK(attempts[hop] < script.size());
        const Step& step = script[attempts[hop]++];
        starts[hop].push_back(clock);
        clock += step.duration;
        // Deliberately plausible garbage on zero returns: none may be consumed.
        ICMPECHO* echo = static_cast<ICMPECHO*>(reply);
        memset(echo, 0, sizeof(*echo));
        echo->Address = htonl(0x0a000001 + hop);
        echo->Status = step.status;
        echo->RoundTripTime = step.rtt;
        return ProbeResult{step.count, step.error};
    }
    DWORD Wait(HANDLE handle, DWORD timeout) override {
        // Clobber the ambient error to expose callers that forget captured errors.
        SetLastError(ERROR_ACCESS_DENIED);
        if (handle == stopHandle && timeout > 0) {
            CHECK(hop >= 0);
            delays[hop].push_back(timeout);
            if (failTimedWait) return WAIT_FAILED;
            if (hop == 0 && attempts[hop] == 1) {
                firstWait.Signal();
                advance.Await();
            }
            if (attempts[hop] < script.size()) {
                clock += timeout;
                return WAIT_TIMEOUT;
            }
            if (hop == 0) ready.Signal();
            return WinMTRNetBackend::Wait(handle, INFINITE);
        }
        return FakeBackend::Wait(handle, timeout);
    }
};
thread_local int ScriptedBackend::hop = -1;
thread_local ULONGLONG ScriptedBackend::clock = 0;

static ScriptedBackend::Step Local(DWORD code = IP_GENERAL_FAILURE, DWORD duration = 0)
{ return {0, code, IP_SUCCESS, duration, 999999}; }
static ScriptedBackend::Step Timeout(DWORD duration)
{ return {0, IP_REQ_TIMED_OUT, IP_SUCCESS, duration, 999999}; }
static ScriptedBackend::Step Reply(DWORD duration = 0, DWORD rtt = 1)
{ return {1, ERROR_SUCCESS, IP_TTL_EXPIRED_TRANSIT, duration, rtt}; }

static void CheckPacing(const std::vector<ScriptedBackend::Step>& script, double interval,
                        const std::vector<ULONGLONG>& starts, const std::vector<DWORD>& delays,
                        WinMTRNet::ProbeOutcome outcome, ULONGLONG initialClock = 0)
{
    ScriptedBackend backend;
    backend.script = script;
    backend.initialClock = initialClock;
    std::unique_ptr<WinMTRNet> net(new WinMTRNet(&backend));
    TraceConfig config = Config();
    config.interval = interval;
    CHECK(net->StartTrace(config));
    backend.ready.Await();
    net->RequestStop();
    Finish(*net);
    CHECK(net->GetStatus().error.empty());
    CHECK(backend.starts[0] == starts);
    CHECK(backend.delays[0] == delays);
    CHECK(net->GetProbeStatus(0).outcome == outcome);
    CHECK(net->GetXmit(0) == static_cast<int>(script.size()));
}

static void FailedProbePacing()
{
    CheckPacing({Local(), Local(), Local()}, 1, {0, 1000, 2000}, {1000, 1000, 1000}, WinMTRNet::LocalError);
    CheckPacing({Local(), Local(), Local()}, 0, {0, 100, 200}, {100, 100, 100}, WinMTRNet::LocalError);
    CheckPacing({Local(IP_NO_RESOURCES, 30), Local()}, .001, {0, 100}, {70, 100}, WinMTRNet::LocalError);
    CheckPacing({Timeout(5000), Timeout(0)}, 10, {0, 10000}, {5000, 10000}, WinMTRNet::Unanswered);
    CheckPacing({Timeout(5000), Timeout(0)}, 1, {0, 5000}, {1000}, WinMTRNet::Unanswered);
}
static void ReplyAndNetworkErrorPacing()
{
    // Duration, not the deliberately different reply RTT, controls scheduling.
    CheckPacing({Reply(80, 1), Reply()}, .1, {0, 100}, {20, 100}, WinMTRNet::Reply);
    CheckPacing({Reply(300, 9999), Reply()}, .1, {0, 300}, {100}, WinMTRNet::Reply);
    CheckPacing({Reply(), Reply()}, 0, {0, 1}, {1, 1}, WinMTRNet::Reply);
    CheckPacing({Reply(), Reply()}, .0001, {0, 1}, {1, 1}, WinMTRNet::Reply);
    CheckPacing({Reply(), Reply()}, .0011, {0, 2}, {2, 2}, WinMTRNet::Reply);
    auto network = Reply();
    network.status = IP_DEST_HOST_UNREACHABLE;
    CheckPacing({network, network}, .1, {0, 100}, {100, 100}, WinMTRNet::NetworkError);
    network.count = 0;
    network.error = IP_DEST_HOST_UNREACHABLE;
    CheckPacing({network, network}, .1, {0, 100}, {100, 100}, WinMTRNet::NetworkError);
    // Unsigned elapsed-time subtraction also survives clock rollover.
    CheckPacing({Reply(20), Reply()}, .1, {~ULONGLONG(0) - 9, 90}, {80, 100},
        WinMTRNet::Reply, ~ULONGLONG(0) - 9);
}
static void ZeroReplyBufferAndDiagnostics()
{
    for (DWORD code : {DWORD(IP_GENERAL_FAILURE), DWORD(IP_REQ_TIMED_OUT), DWORD(ERROR_ACCESS_DENIED), DWORD(0), DWORD(0xfefefefe)}) {
        ScriptedBackend backend;
        backend.script = {Local(code)};
        std::unique_ptr<WinMTRNet> net(new WinMTRNet(&backend));
        CHECK(net->StartTrace(Config(true)));
        backend.ready.Await();
        const auto status = net->GetProbeStatus(0);
        CHECK(status.code == code);
        CHECK(status.outcome == (code == IP_REQ_TIMED_OUT ? WinMTRNet::Unanswered : WinMTRNet::LocalError));
        CHECK(status.message.find(std::to_string(code)) != std::string::npos);
        CHECK(status.message.size() < 300);
        CHECK(status.message.find('\n') == std::string::npos);
        CHECK(net->GetAddr(0) == 0);
        CHECK(net->GetLast(0) == 0);
        CHECK(net->GetReturned(0) == 0);
        CHECK(net->GetXmit(0) == 1);
        CHECK(net->GetPercent(0) == 100); // preserved attempt-count semantics
        CHECK(backend.dnsLaunches == 0);
        CHECK(net->GetStatus().localFailure.empty() == (code == IP_REQ_TIMED_OUT));
        net->RequestStop();
        Finish(*net);
    }
}
static void ErrorRecoveryAndHostnamePreservation()
{
    ScriptedBackend backend;
    backend.script = {Local(), Reply()};
    backend.advance.Reset();
    std::unique_ptr<WinMTRNet> net(new WinMTRNet(&backend));
    CHECK(net->StartTrace(Config(true)));
    backend.firstWait.Await();
    CHECK(!net->GetStatus().localFailure.empty());
    backend.advance.Signal();
    backend.ready.Await();
    Await([&] { return net->GetStatus().localFailure.empty(); });
    char name[255];
    Await([&] { net->GetName(0, name); return std::string(name) == "late-name"; });
    CHECK(net->GetProbeStatus(0).outcome == WinMTRNet::Reply);
    CHECK(net->GetProbeStatus(0).message.empty());
    net->RequestStop();
    Finish(*net);

    ScriptedBackend laterFailure;
    laterFailure.script = {Reply(), Local()};
    std::unique_ptr<WinMTRNet> next(new WinMTRNet(&laterFailure));
    CHECK(next->StartTrace(Config(true)));
    laterFailure.ready.Await();
    Await([&] { next->GetName(0, name); return std::string(name) == "late-name"; });
    CHECK(!next->GetStatus().localFailure.empty());
    CHECK(next->GetProbeStatus(0).outcome == WinMTRNet::LocalError);
    next->RequestStop();
    Finish(*next);
}
static void FatalProbeErrorsAndRestart()
{
    for (DWORD code : {DWORD(ERROR_INVALID_HANDLE), DWORD(ERROR_INVALID_PARAMETER),
            DWORD(ERROR_NOT_SUPPORTED), DWORD(ERROR_INSUFFICIENT_BUFFER), DWORD(IP_BUF_TOO_SMALL)}) {
        ScriptedBackend backend;
        backend.script = {Local(code)};
        std::unique_ptr<WinMTRNet> net(new WinMTRNet(&backend));
        CHECK(net->StartTrace(Config()));
        Finish(*net);
        CHECK(net->GetStatus().phase == WinMTRNet::Idle);
        CHECK(net->GetStatus().error.find(std::to_string(code)) != std::string::npos);
        for (int i = 0; i < WinMTRNet::MAX_HOPS; ++i) CHECK(net->GetXmit(i) <= 1);
        backend.script = {Reply()};
        for (auto& attempt : backend.attempts) attempt = 0;
        CHECK(net->StartTrace(Config()));
        backend.ready.Await();
        CHECK(net->GetStatus().error.empty());
        CHECK(net->GetStatus().localFailure.empty());
        net->RequestStop();
        Finish(*net);
    }
}
static void FailureWaitCancellationAndError()
{
    ScriptedBackend backend;
    backend.script = {Local()};
    std::unique_ptr<WinMTRNet> net(new WinMTRNet(&backend));
    CHECK(net->StartTrace(Config()));
    backend.ready.Await();
    net->RequestStop();
    net->RequestStop();
    Finish(*net);
    CHECK(net->GetXmit(0) == 1);
    CHECK(net->GetStatus().error.empty());

    // Destruction requests cancellation and drains a failed probe's interval.
    ScriptedBackend closing;
    closing.script = {Local()};
    std::unique_ptr<WinMTRNet> closeNet(new WinMTRNet(&closing));
    CHECK(closeNet->StartTrace(Config()));
    closing.ready.Await();
    closeNet.reset();
    CHECK(closing.shutdowns == 1);
    CHECK(closing.starts[0].size() == 1);

    ScriptedBackend failedWait;
    failedWait.script = {Local()};
    failedWait.failTimedWait = true;
    std::unique_ptr<WinMTRNet> next(new WinMTRNet(&failedWait));
    CHECK(next->StartTrace(Config()));
    Finish(*next);
    CHECK(next->GetStatus().error == "Unable to wait for probe interval.");
}
class RawProbeBackend : public WinMTRNetBackend {
public:
    DWORD count = 0;
protected:
    DWORD SendProbe(int, void*, WORD, IPINFO*, void*, DWORD) override {
        SetLastError(IP_REQ_TIMED_OUT);
        return count;
    }
};
static void ImmediateErrorCapture()
{
    RawProbeBackend backend;
    auto result = backend.Probe(0, NULL, 0, NULL, NULL, 0);
    SetLastError(ERROR_ACCESS_DENIED);
    CHECK(result.replyCount == 0);
    CHECK(result.error == IP_REQ_TIMED_OUT);
    backend.count = 1;
    result = backend.Probe(0, NULL, 0, NULL, NULL, 0);
    CHECK(result.replyCount == 1);
    CHECK(result.error == ERROR_SUCCESS); // stale last-error ignored on success
}

static unsigned __stdcall Watchdog(void* argument)
{
    if (WaitForSingleObject(static_cast<HANDLE>(argument), 30000) != WAIT_OBJECT_0) {
        std::fprintf(stderr, "FAIL: lifecycle test suite exceeded 30 seconds\n");
        TerminateProcess(GetCurrentProcess(), 1);
    }
    return 0;
}
int main()
{
    Event done;
    HANDLE watchdog = reinterpret_cast<HANDLE>(_beginthreadex(NULL, 0, Watchdog, done.handle, 0, NULL));
    CHECK(watchdog);
#define RUN(test) test(); std::printf("PASS %s\n", #test)
    RUN(ImmediateStopAndRepeat);
    RUN(SnapshotAndIntervalCancellation);
    RUN(PendingDestination);
    RUN(PendingProbes);
    RUN(PendingDNS);
    RUN(ResolutionFailure);
    RUN(InitializationAndEventFailures);
    RUN(CoordinatorCreationFailure);
    RUN(PartialProbeStartupFailure);
    RUN(DNSCreationFailure);
    RUN(ImmediateWorkerFailure);
    RUN(FailedJoinRetainsOwnership);
    RUN(FailedCompletionPoll);
    RUN(FailedIntervalWait);
    RUN(FailedStopPoll);
    RUN(ImmediateErrorCapture);
    RUN(FailedProbePacing);
    RUN(ReplyAndNetworkErrorPacing);
    RUN(ZeroReplyBufferAndDiagnostics);
    RUN(ErrorRecoveryAndHostnamePreservation);
    RUN(FatalProbeErrorsAndRestart);
    RUN(FailureWaitCancellationAndError);
    CloseDuringOperation(true, false);
    CloseDuringOperation(false, false);
    CloseDuringOperation(false, true);
    std::puts("PASS CloseDuringOperation (destination, probes, DNS)");
    done.Signal();
    CHECK(WaitForSingleObject(watchdog, 3000) == WAIT_OBJECT_0);
    CHECK(CloseHandle(watchdog));
    std::puts("All lifecycle and probe pacing scenarios passed.");
    return 0;
}
