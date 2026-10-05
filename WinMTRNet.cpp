#include "WinMTRNet.h"
#include <ws2tcpip.h>
#include <process.h>
#include <new>
#include <cmath>

namespace {
class Lock {
public:
    explicit Lock(CRITICAL_SECTION& mutex) : mutex(mutex) { EnterCriticalSection(&mutex); }
    ~Lock() { LeaveCriticalSection(&mutex); }
private:
    CRITICAL_SECTION& mutex;
};
}

WinMTRNetBackend::WinMTRNetBackend()
    : socketsStarted(false), library(NULL), icmp(INVALID_HANDLE_VALUE),
      closeFile(NULL), sendEcho(NULL) {}
WinMTRNetBackend::~WinMTRNetBackend() { Shutdown(); }

bool WinMTRNetBackend::Initialize(std::string& error)
{
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data)) {
        error = "Failed initializing Windows sockets.";
        return false;
    }
    socketsStarted = true;
    library = LoadLibraryA("ICMP.DLL");
    if (!library) {
        error = "Unable to load ICMP.DLL.";
        return false;
    }
    CreateFileFn createFile = reinterpret_cast<CreateFileFn>(GetProcAddress(library, "IcmpCreateFile"));
    closeFile = reinterpret_cast<CloseFileFn>(GetProcAddress(library, "IcmpCloseHandle"));
    sendEcho = reinterpret_cast<SendEchoFn>(GetProcAddress(library, "IcmpSendEcho"));
    if (!createFile || !closeFile || !sendEcho) {
        error = "Required ICMP functions are unavailable.";
        return false;
    }
    icmp = createFile();
    if (icmp == INVALID_HANDLE_VALUE) {
        error = "Unable to open the ICMP service.";
        return false;
    }
    return true;
}

void WinMTRNetBackend::Shutdown()
{
    if (icmp != INVALID_HANDLE_VALUE && closeFile) closeFile(icmp);
    icmp = INVALID_HANDLE_VALUE;
    if (library) FreeLibrary(library);
    library = NULL;
    if (socketsStarted) WSACleanup();
    socketsStarted = false;
}
HANDLE WinMTRNetBackend::CreateStopEvent() { return CreateEvent(NULL, TRUE, FALSE, NULL); }
HANDLE WinMTRNetBackend::Launch(unsigned (__stdcall *entry)(void*), void* argument)
{
    return reinterpret_cast<HANDLE>(_beginthreadex(NULL, 0, entry, argument, 0, NULL));
}
DWORD WinMTRNetBackend::Wait(HANDLE handle, DWORD timeout) { return WaitForSingleObject(handle, timeout); }
bool WinMTRNetBackend::ResolveDestination(const std::string& destination, int& address)
{
    // These synchronous IPv4 APIs are available on Windows 7. The coordinator
    // owns the lookup until it returns, including when shutdown was requested.
    addrinfo hints = {};
    hints.ai_family = AF_INET;
    addrinfo* result = NULL;
    if (getaddrinfo(destination.c_str(), NULL, &hints, &result) != 0) return false;
    address = reinterpret_cast<sockaddr_in*>(result->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(result);
    return true;
}
std::string WinMTRNetBackend::ResolveName(int address)
{
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = address;
    char name[NI_MAXHOST] = {};
    if (getnameinfo(reinterpret_cast<sockaddr*>(&addr), sizeof(addr), name,
                    sizeof(name), NULL, 0, 0) == 0) return name;
    InetNtopA(AF_INET, &addr.sin_addr, name, sizeof(name));
    return name;
}
ULONGLONG WinMTRNetBackend::NowMilliseconds() { return GetTickCount64(); }
ProbeResult WinMTRNetBackend::Probe(int address, void* data, WORD size, IPINFO* options,
                                   void* reply, DWORD replySize)
{
    DWORD count = SendProbe(address, data, size, options, reply, replySize);
    // Capture before waits, locks, formatting, or any other Win32 operation.
    DWORD error = count == 0 ? GetLastError() : ERROR_SUCCESS;
    return ProbeResult{count, error};
}
DWORD WinMTRNetBackend::SendProbe(int address, void* data, WORD size, IPINFO* options,
                                 void* reply, DWORD replySize)
{
    return sendEcho(icmp, address, data, size, options, reply, replySize, ECHO_REPLY_TIMEOUT);
}

WinMTRNet::WinMTRNet(WinMTRNetBackend* injected)
    : ownedBackend(injected ? NULL : new WinMTRNetBackend),
      backend(injected ? injected : ownedBackend.get()), initialized(false),
      coordinator(NULL), stopEvent(NULL), last_remote_addr(0)
{
    InitializeCriticalSection(&mutex);
    memset(dnsThreads, 0, sizeof(dnsThreads));
    ResetHops();
    status.phase = Idle;
    initialized = backend->Initialize(status.error);
    // Release resources from partial initialization immediately.
    if (!initialized) backend->Shutdown();
}
WinMTRNet::~WinMTRNet()
{
    RequestStop();
    if (coordinator) {
        Join(coordinator);
        CloseHandle(coordinator);
    }
    if (stopEvent) CloseHandle(stopEvent);
    backend->Shutdown();
    DeleteCriticalSection(&mutex);
}
void WinMTRNet::ResetHops()
{
    Lock lock(mutex);
    memset(host, 0, sizeof(host));
    for (int i = 0; i < MAX_HOSTS; ++i) probeStatus[i] = ProbeStatus{NoProbe, 0, ""};
    last_remote_addr = 0;
}
void WinMTRNet::Fail(const char* message)
{
    {
        Lock lock(mutex);
        if (status.error.empty()) status.error = message;
    }
    RequestStop();
}
void WinMTRNet::SetPhase(Phase phase)
{
    Lock lock(mutex);
    status.phase = phase;
}
WinMTRNet::Status WinMTRNet::GetStatus()
{
    Lock lock(mutex);
    Status snapshot = status;
    snapshot.localFailure.clear();
    const int hops = GetMax();
    for (int i = 0; i < hops; ++i) {
        if (probeStatus[i].outcome == LocalError) {
            snapshot.localFailure = "Local probe failure at hop " + std::to_string(i + 1) +
                ": " + probeStatus[i].message;
            break;
        }
    }
    return snapshot;
}
WinMTRNet::ProbeStatus WinMTRNet::GetProbeStatus(int at)
{
    Lock lock(mutex);
    return probeStatus[at];
}
bool WinMTRNet::StartTrace(const TraceConfig& next)
{
    if (!TryReap()) return false;
    if (!initialized) return false;
    {
        Lock lock(mutex);
        status.error.clear();
    }
    // Only the validation needed to safely snapshot into the existing probe API.
    if (next.destination.empty() || next.packetSize < 64 || next.packetSize > 4096 ||
        !std::isfinite(next.interval) || next.interval < 0 ||
        next.interval * 1000 > static_cast<double>(MAXDWORD - 1)) {
        Fail("Invalid trace configuration.");
        return false;
    }
    try {
        config.reset(new TraceConfig(next));
    } catch (...) {
        Fail("Unable to allocate trace configuration.");
        return false;
    }
    stopEvent = backend->CreateStopEvent();
    if (!stopEvent) {
        Fail("Unable to create trace stop event.");
        config.reset();
        return false;
    }
    ResetHops();
    SetPhase(Resolving);
    coordinator = backend->Launch(Coordinator, this);
    if (!coordinator) {
        Fail("Unable to create trace coordinator.");
        CloseHandle(stopEvent);
        stopEvent = NULL;
        config.reset();
        SetPhase(Idle);
        return false;
    }
    return true;
}
void WinMTRNet::RequestStop()
{
    Lock lock(mutex);
    if (stopEvent && !SetEvent(stopEvent) && status.error.empty())
        status.error = "Unable to signal trace stop event.";
}
bool WinMTRNet::Stopping()
{
    DWORD result = backend->Wait(stopEvent, 0);
    if (result == WAIT_TIMEOUT) return false;
    if (result != WAIT_OBJECT_0) Fail("Unable to inspect trace stop event.");
    return true;
}
void WinMTRNet::Join(HANDLE thread)
{
    if (backend->Wait(thread, INFINITE) == WAIT_OBJECT_0) return;
    Fail("Unable to wait for trace worker.");
    // A failed wait is never evidence of completion. Keep ownership and retry
    // the real handle; even persistent failure must not allow object destruction.
    while (WaitForSingleObject(thread, INFINITE) != WAIT_OBJECT_0) Sleep(10);
}
bool WinMTRNet::TryReap()
{
    if (!coordinator) return true;
    DWORD result = backend->Wait(coordinator, 0);
    if (result == WAIT_TIMEOUT) return false;
    if (result != WAIT_OBJECT_0) {
        Fail("Unable to inspect trace coordinator.");
        return false;
    }
    CloseHandle(coordinator);
    coordinator = NULL;
    CloseHandle(stopEvent);
    stopEvent = NULL;
    config.reset();
    SetPhase(Idle);
    return true;
}
unsigned __stdcall WinMTRNet::Coordinator(void* argument)
{
    static_cast<WinMTRNet*>(argument)->Run();
    return 0;
}
void WinMTRNet::Run()
{
    HANDLE probes[MAX_HOPS] = {};
    int count = 0;
    try {
        int address = 0;
        if (!Stopping()) {
            if (!backend->ResolveDestination(config->destination, address)) {
                if (!Stopping()) Fail("Unable to resolve destination hostname.");
            } else if (!Stopping()) {
                {
                    Lock lock(mutex);
                    last_remote_addr = address;
                }
                SetPhase(Probing);
                for (int ttl = 1; ttl <= MAX_HOPS && !Stopping(); ++ttl) {
                    Lock lock(mutex);
                    if (Stopping()) break;
                    Worker* worker = new(std::nothrow) Worker;
                    if (!worker) { Fail("Unable to allocate probe worker."); break; }
                    worker->net = this;
                    worker->index = ttl - 1;
                    worker->address = address;
                    HANDLE thread = backend->Launch(ProbeWorker, worker);
                    if (!thread) {
                        delete worker;
                        Fail("Unable to create probe worker.");
                        break;
                    }
                    probes[count++] = thread;
                }
            }
        }
    } catch (...) {
        Fail("Unexpected failure starting trace.");
    }
    SetPhase(DrainingProbes);
    for (int i = 0; i < count; ++i) {
        Join(probes[i]);
        CloseHandle(probes[i]);
    }
    // All producers of DNS handles have now exited. DNS workers cannot create
    // additional workers, so the registry is stable while it is drained.
    SetPhase(DrainingDNS);
    for (int i = 0; i < MAX_HOSTS; ++i) {
        if (dnsThreads[i]) {
            Join(dnsThreads[i]);
            CloseHandle(dnsThreads[i]);
            dnsThreads[i] = NULL;
        }
    }
}
unsigned __stdcall WinMTRNet::ProbeWorker(void* argument)
{
    std::unique_ptr<Worker> worker(static_cast<Worker*>(argument));
    try {
        worker->net->ProbeLoop(*worker);
    } catch (...) {
        worker->net->Fail("Unexpected failure in probe worker.");
    }
    return 0;
}
namespace {
bool NetworkFailure(DWORD code)
{
    switch (code) {
    case IP_DEST_NET_UNREACHABLE: case IP_DEST_HOST_UNREACHABLE:
    case IP_DEST_PROT_UNREACHABLE: case IP_DEST_PORT_UNREACHABLE:
    case IP_PACKET_TOO_BIG: case IP_TTL_EXPIRED_TRANSIT:
    case IP_TTL_EXPIRED_REASSEM: case IP_PARAM_PROBLEM: case IP_SOURCE_QUENCH:
        return true;
    default: return false;
    }
}
bool FatalProbeFailure(DWORD code)
{
    return code == ERROR_INVALID_HANDLE || code == ERROR_INVALID_PARAMETER ||
        code == ERROR_NOT_SUPPORTED || code == ERROR_INSUFFICIENT_BUFFER ||
        code == IP_BUF_TOO_SMALL;
}
std::string ProbeMessage(DWORD code)
{
    const char* known = NULL;
    switch (code) {
    case IP_TTL_EXPIRED_TRANSIT: known = "Time to live expired in transit."; break;
    case IP_BUF_TOO_SMALL: known = "Reply buffer too small."; break;
    case IP_DEST_NET_UNREACHABLE: known = "Destination network unreachable."; break;
    case IP_DEST_HOST_UNREACHABLE: known = "Destination host unreachable."; break;
    case IP_DEST_PROT_UNREACHABLE: known = "Destination protocol unreachable."; break;
    case IP_DEST_PORT_UNREACHABLE: known = "Destination port unreachable."; break;
    case IP_NO_RESOURCES: known = "Insufficient IP resources were available."; break;
    case IP_BAD_OPTION: known = "Bad IP option was specified."; break;
    case IP_HW_ERROR: known = "Hardware error occurred."; break;
    case IP_PACKET_TOO_BIG: known = "Packet was too big."; break;
    case IP_REQ_TIMED_OUT: known = "Request timed out."; break;
    case IP_BAD_REQ: known = "Bad request."; break;
    case IP_BAD_ROUTE: known = "Bad route."; break;
    case IP_TTL_EXPIRED_REASSEM: known = "The time to live expired during fragment reassembly."; break;
    case IP_PARAM_PROBLEM: known = "Parameter problem."; break;
    case IP_SOURCE_QUENCH: known = "Datagrams are arriving too fast to be processed and datagrams may have been discarded."; break;
    case IP_OPTION_TOO_BIG: known = "An IP option was too big."; break;
    case IP_BAD_DESTINATION: known = "Bad destination."; break;
    case IP_GENERAL_FAILURE: known = "General failure."; break;
    case ERROR_INVALID_HANDLE: known = "Invalid ICMP handle."; break;
    case ERROR_INVALID_PARAMETER: known = "Invalid ICMP parameters."; break;
    case ERROR_NOT_SUPPORTED: known = "IPv4 ICMP is not supported."; break;
    case ERROR_INSUFFICIENT_BUFFER: known = "Reply buffer too small."; break;
    case ERROR_NOT_ENOUGH_MEMORY: known = "Insufficient memory for ICMP request."; break;
    default: break;
    }
    char message[256] = {};
    if (!known && code != 0) {
        FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, code, 0, message, sizeof(message), NULL);
        // System messages commonly end with CR/LF and spaces.
        size_t length = strlen(message);
        while (length && (message[length - 1] == '\r' || message[length - 1] == '\n' ||
                          message[length - 1] == ' ')) message[--length] = 0;
    }
    std::string description = known ? known : message;
    if (description.empty()) description = code == 0
        ? "ICMP returned no replies without an error code." : "Unknown ICMP error.";
    return description + " (code " + std::to_string(code) + ")";
}
}

void WinMTRNet::ProbeLoop(const Worker& worker)
{
    const int nDataLen = config->packetSize;
    struct ReplyBuffer { ICMPECHO echo; char payload[8192]; };
    std::unique_ptr<char[]> request(new char[nDataLen]);
    std::unique_ptr<ReplyBuffer> reply(new ReplyBuffer);
    IPINFO options = {};
    options.Ttl = static_cast<unsigned char>(worker.index + 1);
    options.Flags = 0x02; // preserve don't-fragment behavior
    memset(request.get(), 32, nDataLen);
    const DWORD interval = static_cast<DWORD>(std::ceil(config->interval * 1000));
    while (!Stopping()) {
        if (worker.index + 1 > GetMax()) break;
        const ULONGLONG started = backend->NowMilliseconds();
        const ProbeResult result = backend->Probe(worker.address, request.get(),
            static_cast<WORD>(nDataLen), &options, reply.get(), sizeof(ReplyBuffer));
        AddXmit(worker.index); // Sent retains its existing API-attempt meaning.
        if (Stopping()) break;
        // A zero return never makes the reply buffer valid.
        const DWORD code = result.replyCount ? reply->echo.Status : result.error;
        ProbeStatus outcome = {LocalError, code, ""};
        if (result.replyCount && (code == IP_SUCCESS || code == IP_TTL_EXPIRED_TRANSIT)) {
            outcome.outcome = Reply;
            SetLast(worker.index, reply->echo.RoundTripTime);
            SetBest(worker.index, reply->echo.RoundTripTime);
            AddReturned(worker.index);
            SetAddr(worker.index, reply->echo.Address);
        } else {
            outcome.outcome = code == IP_REQ_TIMED_OUT ? Unanswered :
                (NetworkFailure(code) ? NetworkError : LocalError);
            outcome.message = ProbeMessage(code);
        }
        {
            Lock lock(mutex);
            probeStatus[worker.index] = outcome;
        }
        if (outcome.outcome == LocalError && FatalProbeFailure(code)) {
            Fail(("ICMP probe failed: " + outcome.message).c_str());
            break;
        }
        // Space starts by actual duration, not RTT; no catch-up bursts.
        DWORD spacing = interval > 0 ? interval : 1;
        if (outcome.outcome == LocalError && spacing < 100) spacing = 100;
        const ULONGLONG elapsed = backend->NowMilliseconds() - started;
        if (elapsed < spacing) {
            DWORD wait = backend->Wait(stopEvent, spacing - static_cast<DWORD>(elapsed));
            if (wait == WAIT_OBJECT_0) break;
            if (wait != WAIT_TIMEOUT) {
                Fail("Unable to wait for probe interval.");
                break;
            }
        }
    }
}

int WinMTRNet::GetAddr(int at)
{
	Lock lock(mutex);
	int addr = ntohl(host[at].addr);
	return addr;
}

int WinMTRNet::GetName(int at, char *n)
{
	Lock lock(mutex);
	if(!strcmp(host[at].name, "")) {
		int addr = GetAddr(at);
		sprintf (	n, "%d.%d.%d.%d",
							(addr >> 24) & 0xff,
							(addr >> 16) & 0xff,
							(addr >> 8) & 0xff,
							addr & 0xff
		);
		if(addr==0)
			strcpy(n,"");
	} else {
		strcpy(n, host[at].name);
	}
	return 0;
}

int WinMTRNet::GetBest(int at)
{
	Lock lock(mutex);
	int ret = host[at].best;
	return ret;
}

int WinMTRNet::GetWorst(int at)
{
	Lock lock(mutex);
	int ret = host[at].worst;
	return ret;
}

int WinMTRNet::GetAvg(int at)
{
	Lock lock(mutex);
	int ret = host[at].returned == 0 ? 0 : host[at].total / host[at].returned;
	return ret;
}

int WinMTRNet::GetPercent(int at)
{
	Lock lock(mutex);
	int ret = (host[at].xmit == 0) ? 0 : (100 - (100 * host[at].returned / host[at].xmit));
	return ret;
}

int WinMTRNet::GetLast(int at)
{
	Lock lock(mutex);
	int ret = host[at].last;
	return ret;
}

int WinMTRNet::GetReturned(int at)
{
	Lock lock(mutex);
	int ret = host[at].returned;
	return ret;
}

int WinMTRNet::GetXmit(int at)
{
	Lock lock(mutex);
	int ret = host[at].xmit;
	return ret;
}

int WinMTRNet::GetMax()
{
	Lock lock(mutex);
	int max = MAX_HOPS;

	// first match: traced address responds on ping requests, and the address is in the hosts list
	for(int i = 0; i < MAX_HOPS; i++) {
		if(host[i].addr == last_remote_addr) {
			max = i + 1;
			break;
		}
	}

	// second match:  traced address doesn't responds on ping requests
	if(max == MAX_HOPS) {
		while((max > 1) && (host[max - 1].addr == host[max - 2].addr) && (host[max - 1].addr != 0) ) max--;
	}

	return max;
}

void WinMTRNet::SetAddr(int at, __int32 addr)
{
    Lock lock(mutex);
    if (host[at].addr != 0 || addr == 0 || Stopping()) return;
    host[at].addr = addr;
    if (!config->useDNS || Stopping()) return;
    Worker* worker = new(std::nothrow) Worker;
    if (!worker) { Fail("Unable to allocate DNS worker."); return; }
    worker->net = this;
    worker->index = at;
    worker->address = addr;
    HANDLE thread = backend->Launch(DNSWorker, worker);
    if (!thread) {
        delete worker;
        Fail("Unable to create DNS worker.");
        return;
    }
    dnsThreads[at] = thread;
}

void WinMTRNet::SetName(int at, const char *n)
{
	Lock lock(mutex);
	strncpy_s(host[at].name, n, _TRUNCATE);
}

void WinMTRNet::SetBest(int at, int current)
{
	Lock lock(mutex);
	if(host[at].best > current || host[at].xmit == 1) {
		host[at].best = current;
	};
	if(host[at].worst < current) {
		host[at].worst = current;
	}

}

void WinMTRNet::SetLast(int at, int last)
{
	Lock lock(mutex);
	host[at].last = last;
	host[at].total += last;
}

void WinMTRNet::AddReturned(int at)
{
	Lock lock(mutex);
	host[at].returned++;
}

void WinMTRNet::AddXmit(int at)
{
	Lock lock(mutex);
	host[at].xmit++;
}


unsigned __stdcall WinMTRNet::DNSWorker(void* argument)
{
    std::unique_ptr<Worker> worker(static_cast<Worker*>(argument));
    WinMTRNet* net = worker->net;
    try {
        if (!net->Stopping()) {
            std::string name = net->backend->ResolveName(worker->address);
            Lock lock(net->mutex);
            // Cancellation and result publication share the session's stop event.
            if (!net->Stopping()) net->SetName(worker->index, name.c_str());
        }
    } catch (...) {
        net->Fail("Unexpected failure in DNS worker.");
    }
    return 0;
}
