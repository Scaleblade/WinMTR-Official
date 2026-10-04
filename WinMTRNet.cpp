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
DWORD WinMTRNetBackend::Probe(int address, void* data, WORD size, IPINFO* options,
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
    return status;
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
void WinMTRNet::ProbeLoop(const Worker& worker)
{
    WinMTRNet* wmtrnet = this;
    const int nDataLen = config->packetSize;
    struct ReplyBuffer { ICMPECHO echo; char payload[8192]; };
    std::unique_ptr<char[]> request(new char[nDataLen]);
    std::unique_ptr<ReplyBuffer> reply(new ReplyBuffer);
    IPINFO stIPInfo = {};
    stIPInfo.Ttl = static_cast<unsigned char>(worker.index + 1);
    stIPInfo.Flags = 0x02; // preserve don't-fragment behavior
    memset(request.get(), 32, nDataLen);
    while (!Stopping()) {
        if (worker.index + 1 > GetMax()) break;
        DWORD dwReplyCount = backend->Probe(worker.address, request.get(),
            static_cast<WORD>(nDataLen), &stIPInfo, reply.get(), sizeof(ReplyBuffer));
        PICMPECHO icmp_echo_reply = &reply->echo;
        AddXmit(worker.index);
        if (Stopping()) break;
        if (dwReplyCount != 0) {
			switch(icmp_echo_reply->Status) {
				case IP_SUCCESS:
				case IP_TTL_EXPIRED_TRANSIT:
					wmtrnet->SetLast(worker.index, icmp_echo_reply->RoundTripTime);
					wmtrnet->SetBest(worker.index, icmp_echo_reply->RoundTripTime);
					wmtrnet->AddReturned(worker.index);
					wmtrnet->SetAddr(worker.index, icmp_echo_reply->Address);
				break;
				case IP_BUF_TOO_SMALL:
					wmtrnet->SetName(worker.index, "Reply buffer too small.");
				break;
				case IP_DEST_NET_UNREACHABLE:
					wmtrnet->SetName(worker.index, "Destination network unreachable.");
				break;
				case IP_DEST_HOST_UNREACHABLE:
					wmtrnet->SetName(worker.index, "Destination host unreachable.");
				break;
				case IP_DEST_PROT_UNREACHABLE:
					wmtrnet->SetName(worker.index, "Destination protocol unreachable.");
				break;
				case IP_DEST_PORT_UNREACHABLE:
					wmtrnet->SetName(worker.index, "Destination port unreachable.");
				break;
				case IP_NO_RESOURCES:
					wmtrnet->SetName(worker.index, "Insufficient IP resources were available.");
				break;
				case IP_BAD_OPTION:
					wmtrnet->SetName(worker.index, "Bad IP option was specified.");
				break;
				case IP_HW_ERROR:
					wmtrnet->SetName(worker.index, "Hardware error occurred.");
				break;
				case IP_PACKET_TOO_BIG:
					wmtrnet->SetName(worker.index, "Packet was too big.");
				break;
				case IP_REQ_TIMED_OUT:
					wmtrnet->SetName(worker.index, "Request timed out.");
				break;
				case IP_BAD_REQ:
					wmtrnet->SetName(worker.index, "Bad request.");
				break;
				case IP_BAD_ROUTE:
					wmtrnet->SetName(worker.index, "Bad route.");
				break;
				case IP_TTL_EXPIRED_REASSEM:
					wmtrnet->SetName(worker.index, "The time to live expired during fragment reassembly.");
				break;
				case IP_PARAM_PROBLEM:
					wmtrnet->SetName(worker.index, "Parameter problem.");
				break;
				case IP_SOURCE_QUENCH:
					wmtrnet->SetName(worker.index, "Datagrams are arriving too fast to be processed and datagrams may have been discarded.");
				break;
				case IP_OPTION_TOO_BIG:
					wmtrnet->SetName(worker.index, "An IP option was too big.");
				break;
				case IP_BAD_DESTINATION:
					wmtrnet->SetName(worker.index, "Bad destination.");
				break;
				case IP_GENERAL_FAILURE:
					wmtrnet->SetName(worker.index, "General failure.");
				break;
				default:
					wmtrnet->SetName(worker.index, "General failure.");
			}

            double delay = config->interval * 1000 - icmp_echo_reply->RoundTripTime;
            if (delay > 0) {
                DWORD result = backend->Wait(stopEvent, static_cast<DWORD>(delay));
                if (result == WAIT_OBJECT_0) break;
                if (result != WAIT_TIMEOUT) {
                    Fail("Unable to wait for probe interval.");
                    break;
                }
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
