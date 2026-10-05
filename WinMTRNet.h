#ifndef WINMTRNET_H_
#define WINMTRNET_H_

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <memory>
#include <string>

typedef IP_OPTION_INFORMATION IPINFO;
#ifdef _WIN64
typedef ICMP_ECHO_REPLY32 ICMPECHO;
#else
typedef ICMP_ECHO_REPLY ICMPECHO;
#endif
typedef ICMPECHO* PICMPECHO;
#define ECHO_REPLY_TIMEOUT 5000

struct TraceConfig {
    std::string destination;
    int packetSize;
    double interval;
    bool useDNS;
};

struct ProbeResult { DWORD replyCount; DWORD error; };

// Injection seam for deterministic lifecycle tests; production uses Win32.
class WinMTRNetBackend {
public:
    WinMTRNetBackend();
    virtual ~WinMTRNetBackend();
    virtual bool Initialize(std::string& error);
    virtual void Shutdown();
    virtual HANDLE CreateStopEvent();
    virtual HANDLE Launch(unsigned (__stdcall *entry)(void*), void* argument);
    virtual DWORD Wait(HANDLE handle, DWORD timeout);
    virtual bool ResolveDestination(const std::string& destination, int& address);
    virtual std::string ResolveName(int address);
    virtual ULONGLONG NowMilliseconds();
    virtual ProbeResult Probe(int address, void* data, WORD size, IPINFO* options,
                        void* reply, DWORD replySize);
protected:
    // Raw API seam also allows testing immediate GetLastError capture.
    virtual DWORD SendProbe(int address, void* data, WORD size, IPINFO* options,
                            void* reply, DWORD replySize);
private:
    typedef HANDLE (WINAPI *CreateFileFn)();
    typedef BOOL (WINAPI *CloseFileFn)(HANDLE);
    typedef DWORD (WINAPI *SendEchoFn)(HANDLE, IPAddr, LPVOID, WORD,
                                     PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD);
    bool socketsStarted;
    HMODULE library;
    HANDLE icmp;
    CloseFileFn closeFile;
    SendEchoFn sendEcho;
};

struct s_nethost {
    __int32 addr;
    int xmit;
    int returned;
    unsigned long total;
    int last;
    int best;
    int worst;
    char name[255];
};

class WinMTRNet {
public:
    enum { MAX_HOSTS = 256, MAX_HOPS = 30 };
    enum Phase { Idle, Resolving, Probing, DrainingProbes, DrainingDNS };
    enum ProbeOutcome { NoProbe, Reply, Unanswered, NetworkError, LocalError };
    struct ProbeStatus { ProbeOutcome outcome; DWORD code; std::string message; };
    struct Status { Phase phase; std::string error; std::string localFailure; };

    // An injected backend must outlive this object. StartTrace/TryReap are
    // UI-owner operations. Workers only use RequestStop and synchronized getters.
    explicit WinMTRNet(WinMTRNetBackend* backend = NULL);
    ~WinMTRNet();
    bool StartTrace(const TraceConfig& config);
    void RequestStop();
    bool TryReap(); // true only after workers finish and owned handles are closed
    Status GetStatus();
    ProbeStatus GetProbeStatus(int at);

    int GetAddr(int at);
    int GetName(int at, char* name);
    int GetBest(int at);
    int GetWorst(int at);
    int GetAvg(int at);
    int GetPercent(int at);
    int GetLast(int at);
    int GetReturned(int at);
    int GetXmit(int at);
    int GetMax();
private:
    WinMTRNet(const WinMTRNet&) = delete;
    WinMTRNet& operator=(const WinMTRNet&) = delete;
    struct Worker { WinMTRNet* net; int index; int address; };
    static unsigned __stdcall Coordinator(void* argument);
    static unsigned __stdcall ProbeWorker(void* argument);
    static unsigned __stdcall DNSWorker(void* argument);
    void Run();
    void ProbeLoop(const Worker& worker);
    void ResetHops();
    bool Stopping();
    void Join(HANDLE thread);
    void Fail(const char* message);
    void SetPhase(Phase phase);
    void SetAddr(int at, __int32 address);
    void SetName(int at, const char* name);
    void SetBest(int at, int current);
    void SetLast(int at, int last);
    void AddReturned(int at);
    void AddXmit(int at);

    std::unique_ptr<WinMTRNetBackend> ownedBackend;
    WinMTRNetBackend* backend;
    bool initialized;
    CRITICAL_SECTION mutex;
    std::unique_ptr<const TraceConfig> config;
    HANDLE coordinator;
    HANDLE stopEvent;
    HANDLE dnsThreads[MAX_HOSTS]; // published under mutex; joined after probes
    s_nethost host[MAX_HOSTS];
    ProbeStatus probeStatus[MAX_HOSTS];
    __int32 last_remote_addr;
    Status status;
};
#endif
