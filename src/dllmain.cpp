#include "patch_internal.hpp"

namespace LunaAGPatch
{
void Initialize()
{
    if (g_initialized)
    {
        return;
    }

    g_initialized = true;

    LoadConfig();
    Log("stage: after config");

    if (!g_patchImports)
    {
        Log("patch imports disabled");
        Log("initialized, enabled=%d rules=%zu", g_enabled ? 1 : 0, g_rules.size());
        return;
    }

    HMODULE ws2 = GetModuleHandleW(L"ws2_32.dll");
    if (!ws2)
    {
        ws2 = LoadLibraryW(L"ws2_32.dll");
    }

    g_connect = reinterpret_cast<ConnectFn>(GetProcAddress(ws2, "connect"));
    g_wsaConnect = reinterpret_cast<WsaConnectFn>(GetProcAddress(ws2, "WSAConnect"));
    g_wsaIoctl = reinterpret_cast<WsaIoctlFn>(GetProcAddress(ws2, "WSAIoctl"));
    g_getaddrinfo = reinterpret_cast<GetAddrInfoFn>(GetProcAddress(ws2, "getaddrinfo"));
    g_getaddrinfoW = reinterpret_cast<GetAddrInfoWFn>(GetProcAddress(ws2, "GetAddrInfoW"));
    g_getProcAddress = reinterpret_cast<GetProcAddressFn>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetProcAddress"));
    if (HMODULE winhttp = GetModuleHandleW(L"winhttp.dll"))
    {
        g_winHttpConnect = reinterpret_cast<WinHttpConnectFn>(GetProcAddress(winhttp, "WinHttpConnect"));
        g_winHttpOpenRequest = reinterpret_cast<WinHttpOpenRequestFn>(GetProcAddress(winhttp, "WinHttpOpenRequest"));
        g_winHttpSendRequest = reinterpret_cast<WinHttpSendRequestFn>(GetProcAddress(winhttp, "WinHttpSendRequest"));
    }
    Log("stage: after resolve connect=%p WSAConnect=%p WSAIoctl=%p GetProcAddress=%p WinHttpSendRequest=%p",
        reinterpret_cast<void*>(g_connect),
        reinterpret_cast<void*>(g_wsaConnect),
        reinterpret_cast<void*>(g_wsaIoctl),
        reinterpret_cast<void*>(g_getProcAddress),
        reinterpret_cast<void*>(g_winHttpSendRequest));

    InstallInlineHooks();

    Log("stage: patch imports begin");
    PatchAllModules();
    Log("stage: patch imports end");

    Log("initialized, enabled=%d rules=%zu", g_enabled ? 1 : 0, g_rules.size());
}

DWORD WINAPI InitThread(void*)
{
    Sleep(1000);

    try
    {
        Initialize();
    }
    catch (...)
    {
        Log("fatal: C++ exception during initialization");
    }

    if (g_keepAlive)
    {
        Log("worker keepalive");
        while (true)
        {
            const DWORD now = GetTickCount();
            if (g_patchImports && now - g_lastPatchTick >= 1000)
            {
                g_lastPatchTick = now;
                PatchAllModules();
            }

            if (g_uiPatch && now - g_lastUiPatchTick >= 3000)
            {
                g_lastUiPatchTick = now;
                PatchLoginModules();
            }

            Sleep(1000);
        }
    }

    return 0;
}
}

extern "C" __declspec(dllexport) void InstallRedirectHooks()
{
    try
    {
        LunaAGPatch::Initialize();
    }
    catch (...)
    {
        LunaAGPatch::Log("fatal: C++ exception during InstallRedirectHooks");
    }
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        LunaAGPatch::g_module = module;
        DisableThreadLibraryCalls(module);
        HANDLE thread = CreateThread(nullptr, 0, &LunaAGPatch::InitThread, nullptr, 0, nullptr);
        if (thread)
        {
            CloseHandle(thread);
        }
    }

    return TRUE;
}
