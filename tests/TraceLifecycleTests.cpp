#include "../WinMTRNet.h"
#include <process.h>
#include <atomic>
#include <cstdio>
#include <stdexcept>

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
    CloseDuringOperation(true, false);
    CloseDuringOperation(false, false);
    CloseDuringOperation(false, true);
    std::puts("PASS CloseDuringOperation (destination, probes, DNS)");
    done.Signal();
    CHECK(WaitForSingleObject(watchdog, 3000) == WAIT_OBJECT_0);
    CHECK(CloseHandle(watchdog));
    std::puts("All 18 lifecycle scenarios passed.");
    return 0;
}
