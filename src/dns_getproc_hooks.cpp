#include "patch_internal.hpp"

namespace LunaAGPatch
{
int WSAAPI HookGetAddrInfo(PCSTR node, PCSTR service, const ADDRINFOA* hints, PADDRINFOA* result)
{
    if (g_logAllDns)
    {
        Log("getaddrinfo node=%s service=%s", node ? node : "(null)", service ? service : "(null)");
    }

    if (g_enabled && node)
    {
        if (auto* rule = FindHostnameRule(node))
        {
            const std::string localService = rule->localPort == 0
                ? (service ? service : "")
                : std::to_string(rule->localPort);
            Log("getaddrinfo %s:%s -> %s:%s",
                node,
                service ? service : "(null)",
                rule->localHost.c_str(),
                localService.c_str());
            RememberResolvedHost(*rule);
            return g_getaddrinfo(
                rule->localHost.c_str(),
                localService.empty() ? nullptr : localService.c_str(),
                hints,
                result);
        }
    }

    return g_getaddrinfo(node, service, hints, result);
}

int WSAAPI HookGetAddrInfoW(PCWSTR node, PCWSTR service, const ADDRINFOW* hints, PADDRINFOW* result)
{
    if (g_logAllDns)
    {
        Log("GetAddrInfoW node=%s service=%s",
            node ? WideToUtf8(node).c_str() : "(null)",
            service ? WideToUtf8(service).c_str() : "(null)");
    }

    if (g_enabled && node)
    {
        const std::string utf8 = WideToUtf8(node);
        if (auto* rule = FindHostnameRule(utf8))
        {
            const std::wstring local = Utf8ToWide(rule->localHost);
            const std::string serviceUtf8 = service ? WideToUtf8(service) : "";
            const std::string localServiceUtf8 = rule->localPort == 0
                ? serviceUtf8
                : std::to_string(rule->localPort);
            const std::wstring localService = Utf8ToWide(localServiceUtf8);
            Log("GetAddrInfoW %s:%s -> %s:%s",
                utf8.c_str(),
                serviceUtf8.empty() ? "(null)" : serviceUtf8.c_str(),
                rule->localHost.c_str(),
                localServiceUtf8.c_str());
            RememberResolvedHost(*rule);
            return g_getaddrinfoW(
                local.c_str(),
                localService.empty() ? nullptr : localService.c_str(),
                hints,
                result);
        }
    }

    return g_getaddrinfoW(node, service, hints, result);
}

FARPROC WINAPI HookGetProcAddress(HMODULE module, LPCSTR procName)
{
    if (!g_getProcAddress)
    {
        return nullptr;
    }

    if (!procName || reinterpret_cast<uintptr_t>(procName) <= 0xFFFF)
    {
        return g_getProcAddress(module, procName);
    }

    if (std::strcmp(procName, "connect") == 0)
    {
        auto real = reinterpret_cast<ConnectFn>(g_getProcAddress(module, procName));
        if (real && real != &HookConnect)
        {
            g_connect = real;
        }
        Log("GetProcAddress connect -> hook");
        return reinterpret_cast<FARPROC>(&HookConnect);
    }

    if (std::strcmp(procName, "WSAConnect") == 0)
    {
        auto real = reinterpret_cast<WsaConnectFn>(g_getProcAddress(module, procName));
        if (real && real != &HookWsaConnect)
        {
            g_wsaConnect = real;
        }
        Log("GetProcAddress WSAConnect -> hook");
        return reinterpret_cast<FARPROC>(&HookWsaConnect);
    }

    if (std::strcmp(procName, "WSAIoctl") == 0)
    {
        auto real = reinterpret_cast<WsaIoctlFn>(g_getProcAddress(module, procName));
        if (real && real != &HookWsaIoctl)
        {
            g_wsaIoctl = real;
        }
        Log("GetProcAddress WSAIoctl -> hook");
        return reinterpret_cast<FARPROC>(&HookWsaIoctl);
    }

    if (std::strcmp(procName, "getaddrinfo") == 0)
    {
        auto real = reinterpret_cast<GetAddrInfoFn>(g_getProcAddress(module, procName));
        if (real && real != &HookGetAddrInfo)
        {
            g_getaddrinfo = real;
        }
        Log("GetProcAddress getaddrinfo -> hook");
        return reinterpret_cast<FARPROC>(&HookGetAddrInfo);
    }

    if (std::strcmp(procName, "GetAddrInfoW") == 0)
    {
        auto real = reinterpret_cast<GetAddrInfoWFn>(g_getProcAddress(module, procName));
        if (real && real != &HookGetAddrInfoW)
        {
            g_getaddrinfoW = real;
        }
        Log("GetProcAddress GetAddrInfoW -> hook");
        return reinterpret_cast<FARPROC>(&HookGetAddrInfoW);
    }

    if (std::strcmp(procName, "WinHttpConnect") == 0)
    {
        auto real = reinterpret_cast<WinHttpConnectFn>(g_getProcAddress(module, procName));
        if (real && real != &HookWinHttpConnect)
        {
            g_winHttpConnect = real;
        }
        Log("GetProcAddress WinHttpConnect -> hook");
        return reinterpret_cast<FARPROC>(&HookWinHttpConnect);
    }

    if (std::strcmp(procName, "WinHttpOpenRequest") == 0)
    {
        auto real = reinterpret_cast<WinHttpOpenRequestFn>(g_getProcAddress(module, procName));
        if (real && real != &HookWinHttpOpenRequest)
        {
            g_winHttpOpenRequest = real;
        }
        Log("GetProcAddress WinHttpOpenRequest -> hook");
        return reinterpret_cast<FARPROC>(&HookWinHttpOpenRequest);
    }

    if (std::strcmp(procName, "WinHttpSendRequest") == 0)
    {
        auto real = reinterpret_cast<WinHttpSendRequestFn>(g_getProcAddress(module, procName));
        if (real && real != &HookWinHttpSendRequest)
        {
            g_winHttpSendRequest = real;
        }
        Log("GetProcAddress WinHttpSendRequest -> hook");
        return reinterpret_cast<FARPROC>(&HookWinHttpSendRequest);
    }

    return g_getProcAddress(module, procName);
}
}
