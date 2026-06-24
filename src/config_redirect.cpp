#include "patch_internal.hpp"

namespace LunaAGPatch
{
std::string ReadIniString(const wchar_t* section, const wchar_t* key, const wchar_t* fallback)
{
    const std::wstring iniPath = g_moduleDir + L"\\LunaAG-Patch.ini";
    std::array<wchar_t, 512> buffer{};
    GetPrivateProfileStringW(section, key, fallback, buffer.data(), static_cast<DWORD>(buffer.size()), iniPath.c_str());
    return WideToUtf8(buffer.data());
}

int ReadIniInt(const wchar_t* section, const wchar_t* key, int fallback)
{
    const std::wstring iniPath = g_moduleDir + L"\\LunaAG-Patch.ini";
    return GetPrivateProfileIntW(section, key, fallback, iniPath.c_str());
}

bool ParseIpv4(const std::string& host, uint32_t& output)
{
    char* end = nullptr;
    unsigned long parts[4]{};
    const char* cursor = host.c_str();

    for (int i = 0; i < 4; ++i)
    {
        parts[i] = std::strtoul(cursor, &end, 10);
        if (end == cursor || parts[i] > 255)
        {
            return false;
        }

        if (i < 3)
        {
            if (*end != '.')
            {
                return false;
            }

            cursor = end + 1;
        }
        else if (*end != '\0')
        {
            return false;
        }
    }

    output = static_cast<uint32_t>(
        (parts[0] << 0) |
        (parts[1] << 8) |
        (parts[2] << 16) |
        (parts[3] << 24));
    return true;
}

uint16_t Swap16(uint16_t value)
{
    return static_cast<uint16_t>((value << 8) | (value >> 8));
}

std::string Ipv4ToString(uint32_t address)
{
    char buffer[INET_ADDRSTRLEN]{};
    std::snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u",
        static_cast<unsigned>((address >> 0) & 0xFF),
        static_cast<unsigned>((address >> 8) & 0xFF),
        static_cast<unsigned>((address >> 16) & 0xFF),
        static_cast<unsigned>((address >> 24) & 0xFF));
    return buffer;
}

void LogSockaddr(const char* api, const sockaddr* name)
{
    if (!g_logAllConnects || !name)
    {
        return;
    }

    if (name->sa_family == AF_INET)
    {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(name);
        const std::string host = Ipv4ToString(ipv4->sin_addr.s_addr);
        const uint16_t port = Swap16(ipv4->sin_port);
        Log("%s %s:%u", api, host.c_str(), port);
        return;
    }

    Log("%s family=%d", api, name->sa_family);
}

void LoadConfig()
{
    g_moduleDir = GetModuleDirectory(g_module);
    g_logPath = g_moduleDir + L"\\LunaAG-Patch.log";
    g_enabled = ReadIniInt(L"Redirect", L"Enabled", 1) != 0;
    g_logEnabled = ReadIniInt(L"Redirect", L"Log", 1) != 0;
    g_consoleEnabled = ReadIniInt(L"Redirect", L"Console", 1) != 0;
    g_patchImports = ReadIniInt(L"Redirect", L"PatchImports", 0) != 0;
    g_logAllConnects = ReadIniInt(L"Redirect", L"LogAllConnects", 1) != 0;
    g_logAllDns = ReadIniInt(L"Redirect", L"LogAllDns", 1) != 0;
    g_patchAllNonSystem = ReadIniInt(L"Redirect", L"PatchAllNonSystem", 1) != 0;
    g_keepAlive = ReadIniInt(L"Redirect", L"KeepAlive", 1) != 0;
    g_uiPatch = ReadIniInt(L"Redirect", L"UiPatch", 1) != 0;
    g_forceLoginCallback = ReadIniInt(L"Redirect", L"ForceLoginCallback", 1) != 0;
    g_inlineHooks = ReadIniInt(L"Redirect", L"InlineHooks", 1) != 0;
    ClearLogFile();
    OpenConsole();
    Log("LunaAG-Patch loaded");
    Log("stage: after console");
    Log("module path: %s", WideToUtf8(GetModulePath(g_module)).c_str());
    Log("config dir: %s", WideToUtf8(g_moduleDir).c_str());
    Log("ui patch enabled=%d force login callback=%d inline hooks=%d",
        g_uiPatch ? 1 : 0,
        g_forceLoginCallback ? 1 : 0,
        g_inlineHooks ? 1 : 0);
    std::array<wchar_t, MAX_PATH> tempPath{};
    if (GetTempPathW(static_cast<DWORD>(tempPath.size()), tempPath.data()) > 0)
    {
        g_captchaFlagPath = std::wstring(tempPath.data()) + L"LunaAG-CaptchaBypass.flag";
        g_forceLoginFlagPath = std::wstring(tempPath.data()) + L"LunaAG-ForceLogin.flag";
        Log("captcha flag path: %s", WideToUtf8(g_captchaFlagPath).c_str());
        Log("force login flag path: %s", WideToUtf8(g_forceLoginFlagPath).c_str());
        ClearPendingSignalFlags();
    }

    if (g_patchImports)
    {
        std::array<wchar_t, MAX_PATH> windowsDir{};
        GetWindowsDirectoryW(windowsDir.data(), static_cast<UINT>(windowsDir.size()));
        g_windowsDir = ToLowerWide(windowsDir.data());
        if (!g_windowsDir.empty() && g_windowsDir.back() != L'\\')
        {
            g_windowsDir += L'\\';
        }
        Log("windows dir: %s", WideToUtf8(g_windowsDir).c_str());
    }

    const int count = ReadIniInt(L"Redirect", L"MapCount", 3);
    for (int i = 0; i < count; ++i)
    {
        wchar_t section[32]{};
        std::swprintf(section, std::size(section), L"Map%d", i);

        RedirectRule rule;
        rule.remoteHost = ToLower(ReadIniString(section, L"RemoteHost", L""));
        rule.remotePort = static_cast<uint16_t>(ReadIniInt(section, L"RemotePort", 0));
        rule.localHost = ReadIniString(section, L"LocalHost", L"127.0.0.1");
        rule.localPort = static_cast<uint16_t>(ReadIniInt(section, L"LocalPort", 0));

        if (rule.remoteHost.empty() || rule.remotePort == 0 || rule.localPort == 0)
        {
            continue;
        }

        ParseIpv4(rule.remoteHost, rule.remoteIpv4);
        if (!ParseIpv4(rule.localHost, rule.localIpv4))
        {
            rule.localIpv4 = 0x0100007F;
            rule.localHost = "127.0.0.1";
        }

        g_rules.push_back(rule);
        Log("map %s:%u -> %s:%u", rule.remoteHost.c_str(), rule.remotePort, rule.localHost.c_str(), rule.localPort);
    }
}

void RememberResolvedHost(const RedirectRule& rule)
{
    for (const auto& existing : g_resolvedHosts)
    {
        if (existing.localIpv4 == rule.localIpv4 && existing.remotePort == rule.remotePort)
        {
            return;
        }
    }

    g_resolvedHosts.push_back({
        rule.remotePort,
        rule.localPort,
        rule.localHost,
        rule.localIpv4,
        rule.remoteHost
    });
}

RedirectRule* FindRule(const sockaddr* name)
{
    if (!g_enabled || !name || name->sa_family != AF_INET)
    {
        return nullptr;
    }

    const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(name);
    const uint16_t port = Swap16(ipv4->sin_port);

    for (auto& rule : g_rules)
    {
        if (rule.remotePort != port)
        {
            continue;
        }

        if (rule.remoteHost == "*" || rule.remoteIpv4 == 0 || rule.remoteIpv4 == ipv4->sin_addr.s_addr)
        {
            return &rule;
        }
    }

    for (const auto& resolved : g_resolvedHosts)
    {
        if (resolved.remotePort == port && resolved.localIpv4 == ipv4->sin_addr.s_addr)
        {
            static RedirectRule resolvedRule;
            resolvedRule.remoteHost = resolved.sourceHost;
            resolvedRule.remotePort = resolved.remotePort;
            resolvedRule.localHost = resolved.localHost;
            resolvedRule.localPort = resolved.localPort;
            resolvedRule.remoteIpv4 = resolved.localIpv4;
            resolvedRule.localIpv4 = resolved.localIpv4;
            return &resolvedRule;
        }
    }

    return nullptr;
}

bool RewriteSockaddr(const sockaddr* input, int inputLength, sockaddr_storage& storage, int& storageLength)
{
    auto* rule = FindRule(input);
    if (!rule)
    {
        return false;
    }

    std::memset(&storage, 0, sizeof(storage));
    std::memcpy(&storage, input, static_cast<size_t>(std::min<int>(inputLength, sizeof(sockaddr_in))));

    auto* ipv4 = reinterpret_cast<sockaddr_in*>(&storage);
    const uint16_t originalPort = Swap16(ipv4->sin_port);
    const uint32_t originalAddress = ipv4->sin_addr.s_addr;
    ipv4->sin_addr.s_addr = rule->localIpv4;
    ipv4->sin_port = Swap16(rule->localPort);
    storageLength = sizeof(sockaddr_in);

    const std::string originalText = Ipv4ToString(originalAddress);
    const std::string localText = Ipv4ToString(rule->localIpv4);
    Log("connect %s:%u -> %s:%u", originalText.c_str(), originalPort, localText.c_str(), rule->localPort);
    return true;
}

int CallOriginalConnect(SOCKET socket, const sockaddr* name, int namelen)
{
    if (g_connectInlineHook.installed)
    {
        std::lock_guard<std::recursive_mutex> lock(g_inlineHookMutex);
        auto* target = reinterpret_cast<ConnectFn>(g_connectInlineHook.target);
        RestoreInlineHook(g_connectInlineHook);
        const int result = target(socket, name, namelen);
        ReapplyInlineHook(g_connectInlineHook);
        return result;
    }

    return g_connect ? g_connect(socket, name, namelen) : SOCKET_ERROR;
}

int CallOriginalWsaConnect(SOCKET socket, const sockaddr* name, int namelen, LPWSABUF callerData, LPWSABUF calleeData, LPQOS sqos, LPQOS gqos)
{
    if (g_wsaConnectInlineHook.installed)
    {
        std::lock_guard<std::recursive_mutex> lock(g_inlineHookMutex);
        auto* target = reinterpret_cast<WsaConnectFn>(g_wsaConnectInlineHook.target);
        RestoreInlineHook(g_wsaConnectInlineHook);
        const int result = target(socket, name, namelen, callerData, calleeData, sqos, gqos);
        ReapplyInlineHook(g_wsaConnectInlineHook);
        return result;
    }

    return g_wsaConnect ? g_wsaConnect(socket, name, namelen, callerData, calleeData, sqos, gqos) : SOCKET_ERROR;
}

int CallOriginalWsaIoctl(SOCKET socket, DWORD ioControlCode, LPVOID inBuffer, DWORD inBufferSize, LPVOID outBuffer, DWORD outBufferSize, LPDWORD bytesReturned, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine)
{
    if (g_wsaIoctlInlineHook.installed)
    {
        std::lock_guard<std::recursive_mutex> lock(g_inlineHookMutex);
        auto* target = reinterpret_cast<WsaIoctlFn>(g_wsaIoctlInlineHook.target);
        RestoreInlineHook(g_wsaIoctlInlineHook);
        const int result = target(socket, ioControlCode, inBuffer, inBufferSize, outBuffer, outBufferSize, bytesReturned, overlapped, completionRoutine);
        ReapplyInlineHook(g_wsaIoctlInlineHook);
        return result;
    }

    return g_wsaIoctl ? g_wsaIoctl(socket, ioControlCode, inBuffer, inBufferSize, outBuffer, outBufferSize, bytesReturned, overlapped, completionRoutine) : SOCKET_ERROR;
}

int WSAAPI HookConnect(SOCKET socket, const sockaddr* name, int namelen)
{
    LogSockaddr("connect", name);

    sockaddr_storage storage{};
    int storageLength = namelen;
    if (RewriteSockaddr(name, namelen, storage, storageLength))
    {
        return CallOriginalConnect(socket, reinterpret_cast<const sockaddr*>(&storage), storageLength);
    }

    return CallOriginalConnect(socket, name, namelen);
}

int WSAAPI HookWsaConnect(SOCKET socket, const sockaddr* name, int namelen, LPWSABUF callerData, LPWSABUF calleeData, LPQOS sqos, LPQOS gqos)
{
    LogSockaddr("WSAConnect", name);

    sockaddr_storage storage{};
    int storageLength = namelen;
    if (RewriteSockaddr(name, namelen, storage, storageLength))
    {
        return CallOriginalWsaConnect(socket, reinterpret_cast<const sockaddr*>(&storage), storageLength, callerData, calleeData, sqos, gqos);
    }

    return CallOriginalWsaConnect(socket, name, namelen, callerData, calleeData, sqos, gqos);
}

BOOL PASCAL HookConnectEx(SOCKET socket, const sockaddr* name, int namelen, PVOID sendBuffer, DWORD sendDataLength, LPDWORD bytesSent, LPOVERLAPPED overlapped)
{
    LogSockaddr("ConnectEx", name);

    sockaddr_storage storage{};
    int storageLength = namelen;
    if (RewriteSockaddr(name, namelen, storage, storageLength))
    {
        return g_connectEx(socket, reinterpret_cast<const sockaddr*>(&storage), storageLength, sendBuffer, sendDataLength, bytesSent, overlapped);
    }

    return g_connectEx(socket, name, namelen, sendBuffer, sendDataLength, bytesSent, overlapped);
}

int WSAAPI HookWsaIoctl(SOCKET socket, DWORD ioControlCode, LPVOID inBuffer, DWORD inBufferSize, LPVOID outBuffer, DWORD outBufferSize, LPDWORD bytesReturned, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine)
{
    const int result = CallOriginalWsaIoctl(socket, ioControlCode, inBuffer, inBufferSize, outBuffer, outBufferSize, bytesReturned, overlapped, completionRoutine);

    if (result == 0 &&
        ioControlCode == SIO_GET_EXTENSION_FUNCTION_POINTER &&
        inBuffer &&
        inBufferSize >= sizeof(GUID) &&
        outBuffer &&
        outBufferSize >= sizeof(void*) &&
        std::memcmp(inBuffer, &kWsaIdConnectEx, sizeof(GUID)) == 0)
    {
        auto** fn = reinterpret_cast<void**>(outBuffer);
        if (*fn && *fn != reinterpret_cast<void*>(&HookConnectEx))
        {
            g_connectEx = reinterpret_cast<ConnectExFn>(*fn);
            *fn = reinterpret_cast<void*>(&HookConnectEx);
            Log("WSAIoctl ConnectEx -> hook");
        }
    }

    return result;
}

RedirectRule* FindHostnameRule(const std::string& node)
{
    const std::string lower = ToLower(node);
    for (auto& rule : g_rules)
    {
        if ((rule.remoteHost == lower || rule.remoteHost == "*") && rule.remoteIpv4 == 0)
        {
            return &rule;
        }
    }

    return nullptr;
}

RedirectRule* FindHostnamePortRule(const std::string& node, uint16_t port)
{
    const std::string lower = ToLower(node);
    for (auto& rule : g_rules)
    {
        if (rule.remotePort != port)
        {
            continue;
        }

        if (rule.remoteHost == lower || rule.remoteHost == "*")
        {
            return &rule;
        }
    }

    return nullptr;
}
}
