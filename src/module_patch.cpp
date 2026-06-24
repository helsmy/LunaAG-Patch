#include "patch_internal.hpp"

namespace LunaAGPatch
{
bool IsReadablePeImage(HMODULE module)
{
    if (!module)
    {
        return false;
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return false;
    }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(reinterpret_cast<const uint8_t*>(module) + dos->e_lfanew);
    return nt->Signature == IMAGE_NT_SIGNATURE;
}

bool IsSystemModule(HMODULE module)
{
    const std::wstring modulePath = ToLowerWide(GetModulePath(module));
    return !g_windowsDir.empty() && StartsWith(modulePath, g_windowsDir);
}

int PatchImport(HMODULE module, const char* importedModule, const char* functionName, void* replacement, void** original)
{
    if (!IsReadablePeImage(module))
    {
        return 0;
    }

    int patchCount = 0;
    auto* base = reinterpret_cast<uint8_t*>(module);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto& directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!directory.VirtualAddress || !directory.Size)
    {
        return 0;
    }

    auto* import = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + directory.VirtualAddress);
    for (; import->Name; ++import)
    {
        const char* moduleName = reinterpret_cast<const char*>(base + import->Name);
        if (_stricmp(moduleName, importedModule) != 0)
        {
            continue;
        }

        auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + import->FirstThunk);
        auto* originalThunk = import->OriginalFirstThunk
            ? reinterpret_cast<IMAGE_THUNK_DATA*>(base + import->OriginalFirstThunk)
            : thunk;

        for (; originalThunk->u1.AddressOfData; ++originalThunk, ++thunk)
        {
            if (IMAGE_SNAP_BY_ORDINAL(originalThunk->u1.Ordinal))
            {
                continue;
            }

            auto* importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + originalThunk->u1.AddressOfData);
            if (std::strcmp(reinterpret_cast<const char*>(importByName->Name), functionName) != 0)
            {
                continue;
            }

            auto** slot = reinterpret_cast<void**>(&thunk->u1.Function);
            if (*slot == replacement)
            {
                continue;
            }

            if (original && *original == nullptr)
            {
                *original = *slot;
            }

            DWORD oldProtect = 0;
            if (VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldProtect))
            {
                *slot = replacement;
                VirtualProtect(slot, sizeof(void*), oldProtect, &oldProtect);
                FlushInstructionCache(GetCurrentProcess(), slot, sizeof(void*));
                ++patchCount;
            }
        }
    }

    return patchCount;
}

void PatchModule(HMODULE module)
{
    if (module == g_module)
    {
        return;
    }

    const std::wstring modulePath = ToLowerWide(GetModulePath(module));
    if (!g_patchAllNonSystem && !IsPatchTargetModule(module))
    {
        return;
    }

    if (IsSystemModule(module))
    {
        return;
    }

    int count = 0;
    count += PatchImport(module, "WS2_32.dll", "connect", reinterpret_cast<void*>(&HookConnect), reinterpret_cast<void**>(&g_connect));
    count += PatchImport(module, "ws2_32.dll", "connect", reinterpret_cast<void*>(&HookConnect), reinterpret_cast<void**>(&g_connect));
    count += PatchImport(module, "WS2_32.dll", "WSAConnect", reinterpret_cast<void*>(&HookWsaConnect), reinterpret_cast<void**>(&g_wsaConnect));
    count += PatchImport(module, "ws2_32.dll", "WSAConnect", reinterpret_cast<void*>(&HookWsaConnect), reinterpret_cast<void**>(&g_wsaConnect));
    count += PatchImport(module, "WS2_32.dll", "WSAIoctl", reinterpret_cast<void*>(&HookWsaIoctl), reinterpret_cast<void**>(&g_wsaIoctl));
    count += PatchImport(module, "ws2_32.dll", "WSAIoctl", reinterpret_cast<void*>(&HookWsaIoctl), reinterpret_cast<void**>(&g_wsaIoctl));
    count += PatchImport(module, "WS2_32.dll", "getaddrinfo", reinterpret_cast<void*>(&HookGetAddrInfo), reinterpret_cast<void**>(&g_getaddrinfo));
    count += PatchImport(module, "ws2_32.dll", "getaddrinfo", reinterpret_cast<void*>(&HookGetAddrInfo), reinterpret_cast<void**>(&g_getaddrinfo));
    count += PatchImport(module, "WS2_32.dll", "GetAddrInfoW", reinterpret_cast<void*>(&HookGetAddrInfoW), reinterpret_cast<void**>(&g_getaddrinfoW));
    count += PatchImport(module, "ws2_32.dll", "GetAddrInfoW", reinterpret_cast<void*>(&HookGetAddrInfoW), reinterpret_cast<void**>(&g_getaddrinfoW));
    count += PatchImport(module, "KERNEL32.dll", "GetProcAddress", reinterpret_cast<void*>(&HookGetProcAddress), reinterpret_cast<void**>(&g_getProcAddress));
    count += PatchImport(module, "kernel32.dll", "GetProcAddress", reinterpret_cast<void*>(&HookGetProcAddress), reinterpret_cast<void**>(&g_getProcAddress));
    count += PatchImport(module, "WINHTTP.dll", "WinHttpConnect", reinterpret_cast<void*>(&HookWinHttpConnect), reinterpret_cast<void**>(&g_winHttpConnect));
    count += PatchImport(module, "winhttp.dll", "WinHttpConnect", reinterpret_cast<void*>(&HookWinHttpConnect), reinterpret_cast<void**>(&g_winHttpConnect));
    count += PatchImport(module, "WINHTTP.dll", "WinHttpOpenRequest", reinterpret_cast<void*>(&HookWinHttpOpenRequest), reinterpret_cast<void**>(&g_winHttpOpenRequest));
    count += PatchImport(module, "winhttp.dll", "WinHttpOpenRequest", reinterpret_cast<void*>(&HookWinHttpOpenRequest), reinterpret_cast<void**>(&g_winHttpOpenRequest));
    count += PatchImport(module, "WINHTTP.dll", "WinHttpSendRequest", reinterpret_cast<void*>(&HookWinHttpSendRequest), reinterpret_cast<void**>(&g_winHttpSendRequest));
    count += PatchImport(module, "winhttp.dll", "WinHttpSendRequest", reinterpret_cast<void*>(&HookWinHttpSendRequest), reinterpret_cast<void**>(&g_winHttpSendRequest));

    if (count > 0)
    {
        Log("patched %d import(s) in %s", count, WideToUtf8(modulePath).c_str());
    }
}

void PatchAllModules()
{
    const DWORD processId = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return;
    }

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry))
    {
        do
        {
            PatchModule(entry.hModule);
        }
        while (Module32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
}

void InstallInlineHooks()
{
    if (!g_inlineHooks)
    {
        Log("inline hooks disabled");
        return;
    }

    HMODULE ws2 = GetModuleHandleW(L"ws2_32.dll");
    if (!ws2)
    {
        ws2 = LoadLibraryW(L"ws2_32.dll");
    }

    if (!ws2)
    {
        Log("inline hooks skipped: ws2_32 unavailable");
        return;
    }

    void* connectTarget = reinterpret_cast<void*>(GetProcAddress(ws2, "connect"));
    void* wsaConnectTarget = reinterpret_cast<void*>(GetProcAddress(ws2, "WSAConnect"));
    void* wsaIoctlTarget = reinterpret_cast<void*>(GetProcAddress(ws2, "WSAIoctl"));

    InstallInlineHook(
        g_connectInlineHook,
        connectTarget,
        reinterpret_cast<void*>(&HookConnect),
        reinterpret_cast<void**>(&g_connect),
        "ws2_32!connect");
    InstallInlineHook(
        g_wsaConnectInlineHook,
        wsaConnectTarget,
        reinterpret_cast<void*>(&HookWsaConnect),
        reinterpret_cast<void**>(&g_wsaConnect),
        "ws2_32!WSAConnect");
    InstallInlineHook(
        g_wsaIoctlInlineHook,
        wsaIoctlTarget,
        reinterpret_cast<void*>(&HookWsaIoctl),
        reinterpret_cast<void**>(&g_wsaIoctl),
        "ws2_32!WSAIoctl");
}
}
