#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <array>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cwctype>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace
{
using HINTERNET = void*;
using INTERNET_PORT = unsigned short;

struct RedirectRule
{
    std::string remoteHost;
    uint16_t remotePort = 0;
    std::string localHost;
    uint16_t localPort = 0;
    uint32_t remoteIpv4 = 0;
    uint32_t localIpv4 = 0;
};

struct ResolvedHost
{
    uint16_t remotePort = 0;
    uint16_t localPort = 0;
    std::string localHost;
    uint32_t localIpv4 = 0;
    std::string sourceHost;
};

using ConnectFn = int (WSAAPI*)(SOCKET, const sockaddr*, int);
using WsaConnectFn = int (WSAAPI*)(SOCKET, const sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
using WsaIoctlFn = int (WSAAPI*)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using ConnectExFn = BOOL (PASCAL*)(SOCKET, const sockaddr*, int, PVOID, DWORD, LPDWORD, LPOVERLAPPED);
using GetAddrInfoFn = int (WSAAPI*)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
using GetAddrInfoWFn = int (WSAAPI*)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
using GetProcAddressFn = FARPROC (WINAPI*)(HMODULE, LPCSTR);
using WinHttpConnectFn = HINTERNET (WINAPI*)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
using WinHttpOpenRequestFn = HINTERNET (WINAPI*)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
using WinHttpSendRequestFn = BOOL (WINAPI*)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
using Il2CppDomainGetFn = void* (*)();
using Il2CppThreadAttachFn = void* (*)(void*);
using Il2CppDomainGetAssembliesFn = void** (*)(void*, size_t*);
using Il2CppAssemblyGetImageFn = void* (*)(void*);
using Il2CppClassFromNameFn = void* (*)(void*, const char*, const char*);
using Il2CppClassGetTypeFn = void* (*)(void*);
using Il2CppTypeGetObjectFn = void* (*)(void*);
using Il2CppClassGetMethodFromNameFn = void* (*)(void*, const char*, int);
using Il2CppClassGetFieldFromNameFn = void* (*)(void*, const char*);
using Il2CppFieldGetOffsetFn = size_t (*)(void*);
using Il2CppRuntimeInvokeFn = void* (*)(void*, void*, void**, void**);
using Il2CppStringNewFn = void* (*)(const char*);
using Il2CppArrayLengthFn = uintptr_t (*)(void*);
using Il2CppObjectNewFn = void* (*)(void*);

HMODULE g_module = nullptr;
HMODULE g_pinnedModule = nullptr;
std::wstring g_moduleDir;
std::wstring g_logPath;
std::wstring g_windowsDir;
std::vector<RedirectRule> g_rules;
std::vector<ResolvedHost> g_resolvedHosts;
std::unordered_map<HINTERNET, std::wstring> g_winHttpRequestPaths;
std::unordered_set<void*> g_patchedLoginModules;
std::mutex g_mutex;
std::recursive_mutex g_inlineHookMutex;
bool g_enabled = true;
bool g_logEnabled = true;
bool g_consoleEnabled = true;
bool g_consoleReady = false;
bool g_safeMode = true;
int g_initLevel = 1;
bool g_patchImports = false;
bool g_logAllConnects = true;
bool g_logAllDns = true;
bool g_patchAllNonSystem = true;
bool g_keepAlive = true;
bool g_uiPatch = true;
bool g_forceLoginCallback = true;
bool g_inlineHooks = true;
bool g_initialized = false;
bool g_logCleared = false;
DWORD g_lastPatchTick = 0;
DWORD g_lastUiPatchTick = 0;
std::wstring g_captchaFlagPath;
std::wstring g_forceLoginFlagPath;

ConnectFn g_connect = nullptr;
WsaConnectFn g_wsaConnect = nullptr;
WsaIoctlFn g_wsaIoctl = nullptr;
ConnectExFn g_connectEx = nullptr;
GetAddrInfoFn g_getaddrinfo = nullptr;
GetAddrInfoWFn g_getaddrinfoW = nullptr;
GetProcAddressFn g_getProcAddress = nullptr;
WinHttpConnectFn g_winHttpConnect = nullptr;
WinHttpOpenRequestFn g_winHttpOpenRequest = nullptr;
WinHttpSendRequestFn g_winHttpSendRequest = nullptr;
Il2CppDomainGetFn g_il2cppDomainGet = nullptr;
Il2CppThreadAttachFn g_il2cppThreadAttach = nullptr;
Il2CppDomainGetAssembliesFn g_il2cppDomainGetAssemblies = nullptr;
Il2CppAssemblyGetImageFn g_il2cppAssemblyGetImage = nullptr;
Il2CppClassFromNameFn g_il2cppClassFromName = nullptr;
Il2CppClassGetTypeFn g_il2cppClassGetType = nullptr;
Il2CppTypeGetObjectFn g_il2cppTypeGetObject = nullptr;
Il2CppClassGetMethodFromNameFn g_il2cppClassGetMethodFromName = nullptr;
Il2CppClassGetFieldFromNameFn g_il2cppClassGetFieldFromName = nullptr;
Il2CppFieldGetOffsetFn g_il2cppFieldGetOffset = nullptr;
Il2CppRuntimeInvokeFn g_il2cppRuntimeInvoke = nullptr;
Il2CppStringNewFn g_il2cppStringNew = nullptr;
Il2CppArrayLengthFn g_il2cppArrayLength = nullptr;
Il2CppObjectNewFn g_il2cppObjectNew = nullptr;
void* g_loginModuleClass = nullptr;
void* g_unityObjectClass = nullptr;
void* g_inputFieldClass = nullptr;
void* g_loginResultClass = nullptr;
void* g_userInfoClass = nullptr;
void* g_logoffApplyClass = nullptr;
void* g_findObjectsOfTypeMethod = nullptr;
void* g_textSetTextMethod = nullptr;
void* g_geetestVerifyCallbackMethod = nullptr;
void* g_innerLoginCallbackMethod = nullptr;
void* g_loginResultCtorMethod = nullptr;
void* g_userInfoCtorMethod = nullptr;
void* g_logoffApplyCtorMethod = nullptr;
bool g_pendingCaptchaBypass = false;
bool g_pendingForceLoginCallback = false;
bool g_forceLoginCallbackDone = false;

constexpr size_t kInvalidOffset = static_cast<size_t>(-1);

struct Il2CppFieldOffsets
{
    size_t loginInputPhone = kInvalidOffset;
    size_t loginRegexp = kInvalidOffset;
    size_t loginGeetestType = kInvalidOffset;

    size_t inputPlaceholder = kInvalidOffset;
    size_t inputContentType = kInvalidOffset;
    size_t inputKeyboardType = kInvalidOffset;
    size_t inputCharacterValidation = kInvalidOffset;

    size_t resultErrorCode = kInvalidOffset;
    size_t resultErrorMsg = kInvalidOffset;
    size_t resultData = kInvalidOffset;

    size_t userUserId = kInvalidOffset;
    size_t userPhone = kInvalidOffset;
    size_t userNickName = kInvalidOffset;
    size_t userHeadUrl = kInvalidOffset;
    size_t userGender = kInvalidOffset;
    size_t userToken = kInvalidOffset;
    size_t userRealNameValid = kInvalidOffset;
    size_t userInviteLimit = kInvalidOffset;
    size_t userRealNameValidResult = kInvalidOffset;
    size_t userAdult = kInvalidOffset;
    size_t userGuest = kInvalidOffset;
    size_t userIndulgeLimitStatus = kInvalidOffset;
    size_t userRealNameUpdateLimit = kInvalidOffset;
    size_t userLogoffApply = kInvalidOffset;
    size_t userSecurityValid = kInvalidOffset;
    size_t userRegionNo = kInvalidOffset;

    size_t logoffDate = kInvalidOffset;
    size_t logoffRemainTime = kInvalidOffset;
    size_t logoffDealStatus = kInvalidOffset;
};

Il2CppFieldOffsets g_offsets;
bool g_offsetsResolved = false;

struct InlineHook
{
    void* target = nullptr;
    void* replacement = nullptr;
    void* trampoline = nullptr;
    uint8_t original[16]{};
    size_t patchSize = 12;
    bool installed = false;
};

InlineHook g_connectInlineHook;
InlineHook g_wsaConnectInlineHook;
InlineHook g_wsaIoctlInlineHook;

constexpr GUID kWsaIdConnectEx = {
    0x25a207b9,
    0xddf3,
    0x4660,
    {0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e}
};

std::string ToLower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string WideToUtf8(const std::wstring& value)
{
    if (value.empty())
    {
        return {};
    }

    const int size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size <= 1)
    {
        return {};
    }

    std::string output(static_cast<size_t>(size - 1), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, output.data(), size, nullptr, nullptr) == 0)
    {
        return {};
    }

    return output;
}

std::wstring Utf8ToWide(const std::string& value)
{
    if (value.empty())
    {
        return {};
    }

    const int size = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
    if (size <= 1)
    {
        return {};
    }

    std::wstring output(static_cast<size_t>(size - 1), L'\0');
    if (MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, output.data(), size) == 0)
    {
        return {};
    }

    return output;
}

bool ReplaceAll(std::string& value, const std::string& from, const std::string& to)
{
    if (from.empty())
    {
        return false;
    }

    bool replaced = false;
    size_t pos = 0;
    while ((pos = value.find(from, pos)) != std::string::npos)
    {
        value.replace(pos, from.size(), to);
        pos += to.size();
        replaced = true;
    }

    return replaced;
}

template <typename T>
T Proc(HMODULE module, const char* name)
{
    return reinterpret_cast<T>(GetProcAddress(module, name));
}

void Log(const char* format, ...);

bool WriteAbsoluteJump(void* address, void* destination, uint8_t* savedBytes = nullptr)
{
    if (!address || !destination)
    {
        return false;
    }

    uint8_t patch[12] = {
        0x48, 0xB8, // mov rax, imm64
        0, 0, 0, 0, 0, 0, 0, 0,
        0xFF, 0xE0  // jmp rax
    };
    std::memcpy(patch + 2, &destination, sizeof(destination));

    DWORD oldProtect = 0;
    if (!VirtualProtect(address, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        return false;
    }

    if (savedBytes)
    {
        std::memcpy(savedBytes, address, sizeof(patch));
    }

    std::memcpy(address, patch, sizeof(patch));
    VirtualProtect(address, sizeof(patch), oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), address, sizeof(patch));
    return true;
}

bool InstallInlineHook(InlineHook& hook, void* target, void* replacement, void** original, const char* name)
{
    if (!target || !replacement || hook.installed)
    {
        return hook.installed;
    }

    auto* targetBytes = static_cast<uint8_t*>(target);
    if (targetBytes[0] == 0x48 && targetBytes[1] == 0xB8 && targetBytes[10] == 0xFF && targetBytes[11] == 0xE0)
    {
        Log("inline hook skipped, already patched: %s", name);
        return false;
    }

    constexpr size_t kPatchSize = 12;
    auto* trampoline = static_cast<uint8_t*>(VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!trampoline)
    {
        Log("inline hook trampoline alloc failed: %s", name);
        return false;
    }

    std::memcpy(trampoline, target, kPatchSize);
    void* resume = targetBytes + kPatchSize;
    WriteAbsoluteJump(trampoline + kPatchSize, resume);

    hook.target = target;
    hook.replacement = replacement;
    hook.trampoline = trampoline;
    hook.patchSize = kPatchSize;

    if (!WriteAbsoluteJump(target, replacement, hook.original))
    {
        VirtualFree(trampoline, 0, MEM_RELEASE);
        hook = {};
        Log("inline hook install failed: %s", name);
        return false;
    }

    hook.installed = true;
    if (original)
    {
        *original = trampoline;
    }

    Log("inline hook installed: %s target=%p trampoline=%p", name, target, trampoline);
    return true;
}

bool RestoreInlineHook(InlineHook& hook)
{
    if (!hook.installed || !hook.target)
    {
        return false;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtect(hook.target, hook.patchSize, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        return false;
    }

    std::memcpy(hook.target, hook.original, hook.patchSize);
    VirtualProtect(hook.target, hook.patchSize, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), hook.target, hook.patchSize);
    return true;
}

bool ReapplyInlineHook(InlineHook& hook)
{
    if (!hook.installed || !hook.target || !hook.replacement)
    {
        return false;
    }

    return WriteAbsoluteJump(hook.target, hook.replacement);
}

void Log(const char* format, ...)
{
    char message[2048]{};
    va_list args;
    va_start(args, format);
    std::vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    SYSTEMTIME now{};
    GetLocalTime(&now);

    if (g_consoleReady)
    {
        std::printf("[%04u-%02u-%02u %02u:%02u:%02u] %s\n",
            now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond, message);
        std::fflush(stdout);
    }

    if (!g_logEnabled || g_logPath.empty())
    {
        return;
    }

    HANDLE file = CreateFileW(
        g_logPath.c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        return;
    }

    char line[2300]{};
    const int lineLength = std::snprintf(line, sizeof(line),
        "[%04u-%02u-%02u %02u:%02u:%02u] %s\r\n",
        now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond, message);
    if (lineLength > 0)
    {
        DWORD written = 0;
        WriteFile(file, line, static_cast<DWORD>(std::min<int>(lineLength, sizeof(line) - 1)), &written, nullptr);
    }

    CloseHandle(file);
}

void ClearLogFile()
{
    if (!g_logEnabled || g_logPath.empty() || g_logCleared)
    {
        return;
    }

    g_logCleared = true;
    HANDLE file = CreateFileW(
        g_logPath.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(file);
    }
}

void OpenConsole()
{
    if (!g_consoleEnabled || g_consoleReady)
    {
        return;
    }

    AllocConsole();

    FILE* unused = nullptr;
    freopen_s(&unused, "CONOUT$", "w", stdout);
    freopen_s(&unused, "CONOUT$", "w", stderr);
    SetConsoleTitleW(L"LunaAG-Patch");
    g_consoleReady = true;
}

std::wstring GetModuleDirectory(HMODULE module)
{
    std::array<wchar_t, MAX_PATH> path{};
    GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
    std::wstring result(path.data());
    const auto slash = result.find_last_of(L"\\/");
    return slash == std::wstring::npos ? L"." : result.substr(0, slash);
}

std::wstring GetModulePath(HMODULE module)
{
    std::array<wchar_t, MAX_PATH> path{};
    GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
    return path.data();
}

std::wstring ToLowerWide(std::wstring value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return value;
}

bool StartsWith(const std::wstring& value, const std::wstring& prefix)
{
    return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
}

bool IsPatchTargetModule(HMODULE module)
{
    const std::wstring modulePath = ToLowerWide(GetModulePath(module));
    if (modulePath.empty())
    {
        return false;
    }

    if (module == GetModuleHandleW(nullptr))
    {
        return true;
    }

    const auto slash = modulePath.find_last_of(L"\\/");
    const std::wstring fileName = slash == std::wstring::npos ? modulePath : modulePath.substr(slash + 1);

    return fileName == L"gameassembly.dll" || fileName == L"unityplayer.dll";
}

void* FindIl2CppClass(const char* namespaze, const char* name)
{
    if (!g_il2cppDomainGet || !g_il2cppDomainGetAssemblies || !g_il2cppAssemblyGetImage || !g_il2cppClassFromName)
    {
        return nullptr;
    }

    size_t count = 0;
    void** assemblies = g_il2cppDomainGetAssemblies(g_il2cppDomainGet(), &count);
    for (size_t i = 0; assemblies && i < count; ++i)
    {
        void* image = g_il2cppAssemblyGetImage(assemblies[i]);
        if (!image)
        {
            continue;
        }

        void* klass = g_il2cppClassFromName(image, namespaze, name);
        if (klass)
        {
            return klass;
        }
    }

    return nullptr;
}

size_t FieldOffset(void* klass, const char* fieldName, size_t fallback)
{
    if (!klass || !g_il2cppClassGetFieldFromName || !g_il2cppFieldGetOffset)
    {
        return fallback;
    }

    void* field = g_il2cppClassGetFieldFromName(klass, fieldName);
    if (!field)
    {
        Log("IL2CPP field not found: %s", fieldName);
        return fallback;
    }

    const size_t offset = g_il2cppFieldGetOffset(field);
    Log("IL2CPP field offset %s = 0x%zx", fieldName, offset);
    return offset;
}

size_t BackingFieldOffset(void* klass, const char* propertyName, size_t fallback)
{
    char backingName[128]{};
    std::snprintf(backingName, sizeof(backingName), "<%s>k__BackingField", propertyName);
    size_t offset = FieldOffset(klass, backingName, kInvalidOffset);
    if (offset != kInvalidOffset)
    {
        return offset;
    }

    return FieldOffset(klass, propertyName, fallback);
}

bool HasOffset(size_t offset)
{
    return offset != kInvalidOffset;
}

void SetObjectField(void* object, size_t offset, void* value)
{
    if (object && HasOffset(offset))
    {
        *reinterpret_cast<void**>(static_cast<uint8_t*>(object) + offset) = value;
    }
}

void SetStringField(void* object, size_t offset, const char* value)
{
    SetObjectField(object, offset, g_il2cppStringNew ? g_il2cppStringNew(value) : nullptr);
}

void SetI64Field(void* object, size_t offset, int64_t value)
{
    if (object && HasOffset(offset))
    {
        *reinterpret_cast<int64_t*>(static_cast<uint8_t*>(object) + offset) = value;
    }
}

void SetI32Field(void* object, size_t offset, int32_t value)
{
    if (object && HasOffset(offset))
    {
        *reinterpret_cast<int32_t*>(static_cast<uint8_t*>(object) + offset) = value;
    }
}

void SetBoolField(void* object, size_t offset, bool value)
{
    if (object && HasOffset(offset))
    {
        *reinterpret_cast<uint8_t*>(static_cast<uint8_t*>(object) + offset) = value ? 1 : 0;
    }
}

bool ResolveIl2CppFieldOffsets()
{
    if (g_offsetsResolved)
    {
        return true;
    }

    if (!g_loginModuleClass || !g_inputFieldClass || !g_loginResultClass || !g_userInfoClass || !g_logoffApplyClass)
    {
        return false;
    }

    g_offsets.loginInputPhone = FieldOffset(g_loginModuleClass, "inputPhone", 0x68);
    g_offsets.loginRegexp = FieldOffset(g_loginModuleClass, "regexp", 0x240);
    g_offsets.loginGeetestType = FieldOffset(g_loginModuleClass, "geetestType", 0x1F8);

    g_offsets.inputPlaceholder = FieldOffset(g_inputFieldClass, "m_Placeholder", 0x110);
    g_offsets.inputContentType = FieldOffset(g_inputFieldClass, "m_ContentType", 0x118);
    g_offsets.inputKeyboardType = FieldOffset(g_inputFieldClass, "m_KeyboardType", 0x124);
    g_offsets.inputCharacterValidation = FieldOffset(g_inputFieldClass, "m_CharacterValidation", 0x130);

    g_offsets.resultErrorCode = BackingFieldOffset(g_loginResultClass, "errorCode", 0x10);
    g_offsets.resultErrorMsg = BackingFieldOffset(g_loginResultClass, "errorMsg", 0x18);
    g_offsets.resultData = BackingFieldOffset(g_loginResultClass, "data", 0x20);

    g_offsets.userUserId = BackingFieldOffset(g_userInfoClass, "userId", 0x10);
    g_offsets.userPhone = BackingFieldOffset(g_userInfoClass, "phone", 0x18);
    g_offsets.userNickName = BackingFieldOffset(g_userInfoClass, "nickName", 0x20);
    g_offsets.userHeadUrl = BackingFieldOffset(g_userInfoClass, "headUrl", 0x28);
    g_offsets.userGender = BackingFieldOffset(g_userInfoClass, "gender", 0x30);
    g_offsets.userToken = BackingFieldOffset(g_userInfoClass, "token", 0x38);
    g_offsets.userRealNameValid = BackingFieldOffset(g_userInfoClass, "realNameValid", 0x40);
    g_offsets.userInviteLimit = BackingFieldOffset(g_userInfoClass, "inviteLimit", 0x41);
    g_offsets.userRealNameValidResult = BackingFieldOffset(g_userInfoClass, "realNameValidResult", 0x48);
    g_offsets.userAdult = BackingFieldOffset(g_userInfoClass, "adult", 0x50);
    g_offsets.userGuest = BackingFieldOffset(g_userInfoClass, "guest", 0x51);
    g_offsets.userIndulgeLimitStatus = BackingFieldOffset(g_userInfoClass, "indulgeLimitStatus", 0x58);
    g_offsets.userRealNameUpdateLimit = BackingFieldOffset(g_userInfoClass, "realNameUpdateLimit", 0x60);
    g_offsets.userLogoffApply = BackingFieldOffset(g_userInfoClass, "logoffApply", 0x68);
    g_offsets.userSecurityValid = BackingFieldOffset(g_userInfoClass, "securityValid", 0x70);
    g_offsets.userRegionNo = BackingFieldOffset(g_userInfoClass, "regionNo", 0x78);

    g_offsets.logoffDate = BackingFieldOffset(g_logoffApplyClass, "logoffDate", 0x10);
    g_offsets.logoffRemainTime = BackingFieldOffset(g_logoffApplyClass, "logoffRemainTime", 0x18);
    g_offsets.logoffDealStatus = BackingFieldOffset(g_logoffApplyClass, "dealStatus", 0x20);

    g_offsetsResolved = true;
    return true;
}

bool ResolveIl2CppUiPatch()
{
    if (g_findObjectsOfTypeMethod && g_loginModuleClass && g_textSetTextMethod)
    {
        return true;
    }

    HMODULE gameAssembly = GetModuleHandleW(L"GameAssembly.dll");
    if (!gameAssembly)
    {
        return false;
    }

    g_il2cppDomainGet = Proc<Il2CppDomainGetFn>(gameAssembly, "il2cpp_domain_get");
    g_il2cppThreadAttach = Proc<Il2CppThreadAttachFn>(gameAssembly, "il2cpp_thread_attach");
    g_il2cppDomainGetAssemblies = Proc<Il2CppDomainGetAssembliesFn>(gameAssembly, "il2cpp_domain_get_assemblies");
    g_il2cppAssemblyGetImage = Proc<Il2CppAssemblyGetImageFn>(gameAssembly, "il2cpp_assembly_get_image");
    g_il2cppClassFromName = Proc<Il2CppClassFromNameFn>(gameAssembly, "il2cpp_class_from_name");
    g_il2cppClassGetType = Proc<Il2CppClassGetTypeFn>(gameAssembly, "il2cpp_class_get_type");
    g_il2cppTypeGetObject = Proc<Il2CppTypeGetObjectFn>(gameAssembly, "il2cpp_type_get_object");
    g_il2cppClassGetMethodFromName = Proc<Il2CppClassGetMethodFromNameFn>(gameAssembly, "il2cpp_class_get_method_from_name");
    g_il2cppClassGetFieldFromName = Proc<Il2CppClassGetFieldFromNameFn>(gameAssembly, "il2cpp_class_get_field_from_name");
    g_il2cppFieldGetOffset = Proc<Il2CppFieldGetOffsetFn>(gameAssembly, "il2cpp_field_get_offset");
    g_il2cppRuntimeInvoke = Proc<Il2CppRuntimeInvokeFn>(gameAssembly, "il2cpp_runtime_invoke");
    g_il2cppStringNew = Proc<Il2CppStringNewFn>(gameAssembly, "il2cpp_string_new");
    g_il2cppArrayLength = Proc<Il2CppArrayLengthFn>(gameAssembly, "il2cpp_array_length");
    g_il2cppObjectNew = Proc<Il2CppObjectNewFn>(gameAssembly, "il2cpp_object_new");

    if (!g_il2cppDomainGet || !g_il2cppThreadAttach || !g_il2cppClassGetType ||
        !g_il2cppTypeGetObject || !g_il2cppClassGetMethodFromName ||
        !g_il2cppClassGetFieldFromName || !g_il2cppFieldGetOffset ||
        !g_il2cppRuntimeInvoke || !g_il2cppStringNew || !g_il2cppArrayLength || !g_il2cppObjectNew)
    {
        return false;
    }

    g_il2cppThreadAttach(g_il2cppDomainGet());

    g_loginModuleClass = FindIl2CppClass("YSSDKCore", "LoginModule");
    g_unityObjectClass = FindIl2CppClass("UnityEngine", "Object");
    g_inputFieldClass = FindIl2CppClass("UnityEngine.UI", "InputField");
    g_loginResultClass = FindIl2CppClass("YSSDKCore", "Ys4FunLoginResult");
    g_userInfoClass = FindIl2CppClass("YSSDKCore", "UserInfo");
    g_logoffApplyClass = FindIl2CppClass("YSSDKCore", "LogoffApply");
    void* textClass = FindIl2CppClass("UnityEngine.UI", "Text");
    if (!g_loginModuleClass || !g_unityObjectClass || !g_inputFieldClass ||
        !g_loginResultClass || !g_userInfoClass || !g_logoffApplyClass || !textClass)
    {
        return false;
    }

    g_findObjectsOfTypeMethod = g_il2cppClassGetMethodFromName(g_unityObjectClass, "FindObjectsOfType", 1);
    g_textSetTextMethod = g_il2cppClassGetMethodFromName(textClass, "set_text", 1);
    g_geetestVerifyCallbackMethod = g_il2cppClassGetMethodFromName(g_loginModuleClass, "GeetestVerifyCallback", 4);
    g_innerLoginCallbackMethod = g_il2cppClassGetMethodFromName(g_loginModuleClass, "InnerLoginCallback", 5);
    g_loginResultCtorMethod = g_il2cppClassGetMethodFromName(g_loginResultClass, ".ctor", 0);
    g_userInfoCtorMethod = g_il2cppClassGetMethodFromName(g_userInfoClass, ".ctor", 0);
    g_logoffApplyCtorMethod = g_il2cppClassGetMethodFromName(g_logoffApplyClass, ".ctor", 0);
    if (!g_findObjectsOfTypeMethod || !g_textSetTextMethod || !g_geetestVerifyCallbackMethod ||
        !g_innerLoginCallbackMethod || !g_loginResultCtorMethod || !g_userInfoCtorMethod || !g_logoffApplyCtorMethod)
    {
        return false;
    }

    Log("IL2CPP UI patch resolved LoginModule=%p FindObjectsOfType=%p Text.set_text=%p GeetestVerifyCallback=%p InnerLoginCallback=%p",
        g_loginModuleClass,
        g_findObjectsOfTypeMethod,
        g_textSetTextMethod,
        g_geetestVerifyCallbackMethod,
        g_innerLoginCallbackMethod);
    ResolveIl2CppFieldOffsets();
    return true;
}

void SetUnityText(void* textObject, const char* value)
{
    if (!textObject || !g_textSetTextMethod || !g_il2cppStringNew || !g_il2cppRuntimeInvoke)
    {
        return;
    }

    void* text = g_il2cppStringNew(value);
    void* args[] = { text };
    void* exception = nullptr;
    g_il2cppRuntimeInvoke(g_textSetTextMethod, textObject, args, &exception);
    if (exception)
    {
        Log("IL2CPP Text.set_text exception");
    }
}

void PatchLoginModuleObject(void* loginModule)
{
    if (!loginModule || !g_il2cppStringNew)
    {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_patchedLoginModules.contains(loginModule))
        {
            return;
        }
        g_patchedLoginModules.insert(loginModule);
    }

    ResolveIl2CppFieldOffsets();

    SetStringField(loginModule, g_offsets.loginRegexp, "^.+$");

    void* inputPhone = HasOffset(g_offsets.loginInputPhone)
        ? *reinterpret_cast<void**>(static_cast<uint8_t*>(loginModule) + g_offsets.loginInputPhone)
        : nullptr;
    if (inputPhone)
    {
        SetI32Field(inputPhone, g_offsets.inputContentType, 0);
        SetI32Field(inputPhone, g_offsets.inputKeyboardType, 0);
        SetI32Field(inputPhone, g_offsets.inputCharacterValidation, 0);

        void* placeholder = HasOffset(g_offsets.inputPlaceholder)
            ? *reinterpret_cast<void**>(static_cast<uint8_t*>(inputPhone) + g_offsets.inputPlaceholder)
            : nullptr;
        SetUnityText(placeholder, "请输入用户名");
    }

    Log("LoginModule UI patched object=%p inputPhone=%p", loginModule, inputPhone);
}

bool BypassCaptchaForLoginModule(void* loginModule)
{
    if (!loginModule || !g_geetestVerifyCallbackMethod || !g_il2cppStringNew || !g_il2cppRuntimeInvoke)
    {
        return false;
    }

    int resultCode = 0;
    ResolveIl2CppFieldOffsets();
    int geetestType = HasOffset(g_offsets.loginGeetestType)
        ? *reinterpret_cast<int*>(static_cast<uint8_t*>(loginModule) + g_offsets.loginGeetestType)
        : 1;
    if (geetestType == 0)
    {
        geetestType = 1;
    }

    void* message = g_il2cppStringNew("");
    void* captchaJsonData = g_il2cppStringNew("{}");
    void* args[] = { &resultCode, message, &geetestType, captchaJsonData };
    void* exception = nullptr;
    Log("calling GeetestVerifyCallback object=%p type=%d", loginModule, geetestType);
    g_il2cppRuntimeInvoke(g_geetestVerifyCallbackMethod, loginModule, args, &exception);
    if (exception)
    {
        Log("GeetestVerifyCallback exception");
        return false;
    }

    Log("GeetestVerifyCallback bypassed");
    return true;
}

bool InvokeDefaultCtor(void* object, void* ctorMethod, const char* name)
{
    if (!object || !ctorMethod || !g_il2cppRuntimeInvoke)
    {
        return false;
    }

    void* exception = nullptr;
    g_il2cppRuntimeInvoke(ctorMethod, object, nullptr, &exception);
    if (exception)
    {
        Log("IL2CPP %s .ctor exception", name);
        return false;
    }

    return true;
}

void* CreateLocalLoginResult()
{
    if (!g_il2cppObjectNew || !g_il2cppStringNew || !g_loginResultClass || !g_userInfoClass || !g_logoffApplyClass)
    {
        return nullptr;
    }

    void* result = g_il2cppObjectNew(g_loginResultClass);
    void* user = g_il2cppObjectNew(g_userInfoClass);
    void* logoffApply = g_il2cppObjectNew(g_logoffApplyClass);
    if (!result || !user || !logoffApply)
    {
        Log("force login object allocation failed result=%p user=%p logoff=%p", result, user, logoffApply);
        return nullptr;
    }

    InvokeDefaultCtor(result, g_loginResultCtorMethod, "Ys4FunLoginResult");
    InvokeDefaultCtor(user, g_userInfoCtorMethod, "UserInfo");
    InvokeDefaultCtor(logoffApply, g_logoffApplyCtorMethod, "LogoffApply");
    ResolveIl2CppFieldOffsets();

    SetStringField(result, g_offsets.resultErrorCode, "0");
    SetStringField(result, g_offsets.resultErrorMsg, "");
    SetObjectField(result, g_offsets.resultData, user);

    SetI64Field(user, g_offsets.userUserId, 3000000000LL);
    SetStringField(user, g_offsets.userPhone, "");
    SetStringField(user, g_offsets.userNickName, "LunaAG Local");
    SetStringField(user, g_offsets.userHeadUrl, "");
    SetStringField(user, g_offsets.userGender, "");
    SetStringField(user, g_offsets.userToken, "local-token");
    SetBoolField(user, g_offsets.userRealNameValid, true);
    SetBoolField(user, g_offsets.userInviteLimit, false);
    SetStringField(user, g_offsets.userRealNameValidResult, "");
    SetBoolField(user, g_offsets.userAdult, true);
    SetBoolField(user, g_offsets.userGuest, false);
    SetStringField(user, g_offsets.userIndulgeLimitStatus, "");
    SetI32Field(user, g_offsets.userRealNameUpdateLimit, 0);
    SetObjectField(user, g_offsets.userLogoffApply, logoffApply);
    SetBoolField(user, g_offsets.userSecurityValid, false);
    SetStringField(user, g_offsets.userRegionNo, "86");

    const int64_t nowMs = static_cast<int64_t>(GetTickCount64());
    SetI64Field(logoffApply, g_offsets.logoffDate, nowMs);
    SetI32Field(logoffApply, g_offsets.logoffRemainTime, 0);
    SetStringField(logoffApply, g_offsets.logoffDealStatus, "INVALID");

    return result;
}

bool ForceLoginSuccessForLoginModule(void* loginModule)
{
    if (!loginModule || !g_innerLoginCallbackMethod || !g_il2cppRuntimeInvoke || !g_il2cppStringNew)
    {
        return false;
    }

    void* result = CreateLocalLoginResult();
    if (!result)
    {
        return false;
    }

    int code = 0;
    void* message = g_il2cppStringNew("");
    bool isLoginByPwd = true;
    void* pwd = g_il2cppStringNew("");
    void* args[] = { &code, message, result, &isLoginByPwd, pwd };
    void* exception = nullptr;
    Log("calling InnerLoginCallback object=%p result=%p", loginModule, result);
    g_il2cppRuntimeInvoke(g_innerLoginCallbackMethod, loginModule, args, &exception);
    if (exception)
    {
        Log("InnerLoginCallback force exception");
        return false;
    }

    Log("InnerLoginCallback forced success");
    return true;
}

bool ConsumeCaptchaBypassFlag()
{
    if (g_captchaFlagPath.empty())
    {
        std::array<wchar_t, MAX_PATH> tempPath{};
        const DWORD length = GetTempPathW(static_cast<DWORD>(tempPath.size()), tempPath.data());
        if (length == 0 || length >= tempPath.size())
        {
            return false;
        }
        g_captchaFlagPath = std::wstring(tempPath.data()) + L"LunaAG-CaptchaBypass.flag";
    }

    const DWORD attributes = GetFileAttributesW(g_captchaFlagPath.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        return false;
    }

    DeleteFileW(g_captchaFlagPath.c_str());
    Log("captcha bypass flag consumed: %s", WideToUtf8(g_captchaFlagPath).c_str());
    return true;
}

bool ConsumeForceLoginFlag()
{
    if (g_forceLoginFlagPath.empty())
    {
        std::array<wchar_t, MAX_PATH> tempPath{};
        const DWORD length = GetTempPathW(static_cast<DWORD>(tempPath.size()), tempPath.data());
        if (length == 0 || length >= tempPath.size())
        {
            return false;
        }
        g_forceLoginFlagPath = std::wstring(tempPath.data()) + L"LunaAG-ForceLogin.flag";
    }

    const DWORD attributes = GetFileAttributesW(g_forceLoginFlagPath.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        return false;
    }

    DeleteFileW(g_forceLoginFlagPath.c_str());
    Log("force login flag consumed: %s", WideToUtf8(g_forceLoginFlagPath).c_str());
    return true;
}

void ClearPendingSignalFlags()
{
    if (!g_captchaFlagPath.empty() && DeleteFileW(g_captchaFlagPath.c_str()))
    {
        Log("cleared stale captcha flag");
    }

    if (!g_forceLoginFlagPath.empty() && DeleteFileW(g_forceLoginFlagPath.c_str()))
    {
        Log("cleared stale force login flag");
    }
}

void PatchLoginModules()
{
    if (!g_uiPatch || !ResolveIl2CppUiPatch())
    {
        return;
    }

    void* type = g_il2cppTypeGetObject(g_il2cppClassGetType(g_loginModuleClass));
    void* args[] = { type };
    void* exception = nullptr;
    void* array = g_il2cppRuntimeInvoke(g_findObjectsOfTypeMethod, nullptr, args, &exception);
    if (exception || !array)
    {
        if (exception)
        {
            Log("FindObjectsOfType(LoginModule) exception");
        }
        return;
    }

    const uintptr_t count = g_il2cppArrayLength(array);
    if (count > 0)
    {
        Log("LoginModule found count=%zu", static_cast<size_t>(count));
    }

    auto* data = reinterpret_cast<void**>(static_cast<uint8_t*>(array) + 0x20);
    for (uintptr_t i = 0; i < count; ++i)
    {
        PatchLoginModuleObject(data[i]);
    }

    bool shouldBypassCaptcha = false;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        shouldBypassCaptcha = g_pendingCaptchaBypass;
    }

    if (!shouldBypassCaptcha)
    {
        shouldBypassCaptcha = ConsumeCaptchaBypassFlag();
    }

    if (shouldBypassCaptcha && count > 0 && BypassCaptchaForLoginModule(data[0]))
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_pendingCaptchaBypass = false;
    }

    bool shouldForceLogin = false;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        shouldForceLogin = g_forceLoginCallback && g_pendingForceLoginCallback && !g_forceLoginCallbackDone;
    }

    if (!shouldForceLogin && g_forceLoginCallback && !g_forceLoginCallbackDone)
    {
        shouldForceLogin = ConsumeForceLoginFlag();
    }

    if (shouldForceLogin && count > 0 && ForceLoginSuccessForLoginModule(data[0]))
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_forceLoginCallbackDone = true;
        g_pendingForceLoginCallback = false;
    }
}

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

HINTERNET WINAPI HookWinHttpConnect(HINTERNET session, LPCWSTR serverName, INTERNET_PORT serverPort, DWORD reserved)
{
    if (!g_winHttpConnect)
    {
        return nullptr;
    }

    const std::string host = serverName ? WideToUtf8(serverName) : "";
    Log("WinHttpConnect %s:%u", host.empty() ? "(null)" : host.c_str(), static_cast<unsigned>(serverPort));

    if (auto* rule = FindHostnamePortRule(host, static_cast<uint16_t>(serverPort)))
    {
        const std::wstring localHost = Utf8ToWide(rule->localHost);
        Log("WinHttpConnect %s:%u -> %s:%u",
            host.c_str(),
            static_cast<unsigned>(serverPort),
            rule->localHost.c_str(),
            rule->localPort);
        return g_winHttpConnect(session, localHost.c_str(), rule->localPort, reserved);
    }

    return g_winHttpConnect(session, serverName, serverPort, reserved);
}

HINTERNET WINAPI HookWinHttpOpenRequest(HINTERNET connect, LPCWSTR verb, LPCWSTR objectName, LPCWSTR version, LPCWSTR referrer, LPCWSTR* acceptTypes, DWORD flags)
{
    if (!g_winHttpOpenRequest)
    {
        return nullptr;
    }

    std::wstring patchedObjectName;
    LPCWSTR requestObjectName = objectName;
    if (objectName)
    {
        patchedObjectName = objectName;
        const std::wstring originalObjectName = patchedObjectName;

        const std::pair<const wchar_t*, const wchar_t*> replacements[] = {
            {L"/sdk-api/pass/user/loginByPhoneValid", L"/sdk-api/pass/user/loginByLoginName"},
            {L"/pass/user/loginByPhoneValid", L"/pass/user/loginByLoginName"},
            {L"/sdk-api/pass/user/registerBySms", L"/sdk-api/pass/user/loginByLoginName"},
            {L"/pass/user/registerBySms", L"/pass/user/loginByLoginName"},
        };

        for (const auto& replacement : replacements)
        {
            const auto pos = patchedObjectName.find(replacement.first);
            if (pos != std::wstring::npos)
            {
                patchedObjectName.replace(pos, std::wcslen(replacement.first), replacement.second);
                break;
            }
        }

        if (patchedObjectName != originalObjectName)
        {
            Log("WinHttpOpenRequest login path %s -> %s",
                WideToUtf8(originalObjectName).c_str(),
                WideToUtf8(patchedObjectName).c_str());
            requestObjectName = patchedObjectName.c_str();
        }
    }

    constexpr DWORD WINHTTP_FLAG_SECURE_LOCAL = 0x00800000;
    if ((flags & WINHTTP_FLAG_SECURE_LOCAL) != 0)
    {
        Log("WinHttpOpenRequest secure cleared path=%s", requestObjectName ? WideToUtf8(requestObjectName).c_str() : "(null)");
        flags &= ~WINHTTP_FLAG_SECURE_LOCAL;
    }

    HINTERNET request = g_winHttpOpenRequest(connect, verb, requestObjectName, version, referrer, acceptTypes, flags);
    if (request && requestObjectName)
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_winHttpRequestPaths[request] = requestObjectName;
        if (std::wstring(requestObjectName).find(L"/pass/captcha/init") != std::wstring::npos)
        {
            g_pendingCaptchaBypass = true;
            Log("captcha init detected, pending bypass path=%s", WideToUtf8(requestObjectName).c_str());
        }
    }

    return request;
}

BOOL WINAPI HookWinHttpSendRequest(HINTERNET request, LPCWSTR headers, DWORD headersLength, LPVOID optional, DWORD optionalLength, DWORD totalLength, DWORD_PTR context)
{
    if (!g_winHttpSendRequest)
    {
        return FALSE;
    }

    std::wstring requestPath;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_winHttpRequestPaths.find(request);
        if (it != g_winHttpRequestPaths.end())
        {
            requestPath = it->second;
        }
    }

    std::string patchedBody;
    LPVOID requestOptional = optional;
    DWORD requestOptionalLength = optionalLength;
    DWORD requestTotalLength = totalLength;

    const bool isLoginNameRequest = requestPath.find(L"/pass/user/loginByLoginName") != std::wstring::npos
        || requestPath.find(L"/sdk-api/pass/user/loginByLoginName") != std::wstring::npos;
    const bool isLoginRequest = requestPath.find(L"/pass/user/login") != std::wstring::npos
        || requestPath.find(L"/sdk-api/pass/user/login") != std::wstring::npos;
    if (isLoginNameRequest && optional && optionalLength > 0)
    {
        const auto* body = static_cast<const char*>(optional);
        patchedBody.assign(body, body + optionalLength);

        bool replaced = false;
        replaced = ReplaceAll(patchedBody, "phone=", "loginName=") || replaced;
        replaced = ReplaceAll(patchedBody, "mobile=", "loginName=") || replaced;
        replaced = ReplaceAll(patchedBody, "phoneNumber=", "loginName=") || replaced;

        if (replaced)
        {
            requestOptional = patchedBody.data();
            requestOptionalLength = static_cast<DWORD>(patchedBody.size());
            if (totalLength == optionalLength)
            {
                requestTotalLength = requestOptionalLength;
            }
            Log("WinHttpSendRequest login body keys patched path=%s oldLen=%u newLen=%u",
                WideToUtf8(requestPath).c_str(),
                static_cast<unsigned>(optionalLength),
                static_cast<unsigned>(requestOptionalLength));
        }
    }

    if (g_forceLoginCallback && isLoginRequest)
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_forceLoginCallbackDone)
        {
            g_pendingForceLoginCallback = true;
            Log("force login callback pending path=%s", WideToUtf8(requestPath).c_str());
        }
    }

    return g_winHttpSendRequest(request, headers, headersLength, requestOptional, requestOptionalLength, requestTotalLength, context);
}

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

void Initialize()
{
    if (g_initialized)
    {
        return;
    }

    g_initialized = true;

    g_moduleDir = GetModuleDirectory(g_module);
    const std::wstring iniPath = g_moduleDir + L"\\LunaAG-Patch.ini";
    g_initLevel = GetPrivateProfileIntW(L"Redirect", L"InitLevel", 1, iniPath.c_str());

    if (g_initLevel <= 1)
    {
        AllocConsole();
        FILE* unused = nullptr;
        freopen_s(&unused, "CONOUT$", "w", stdout);
        freopen_s(&unused, "CONOUT$", "w", stderr);
        SetConsoleTitleW(L"LunaAG-Patch");
        std::printf("LunaAG-Patch InitLevel=1 loaded\n");
        std::fflush(stdout);
        return;
    }

    if (g_initLevel == 2)
    {
        g_logPath = g_moduleDir + L"\\LunaAG-Patch.log";
        g_logEnabled = GetPrivateProfileIntW(L"Redirect", L"Log", 1, iniPath.c_str()) != 0;
        g_consoleEnabled = GetPrivateProfileIntW(L"Redirect", L"Console", 1, iniPath.c_str()) != 0;
        ClearLogFile();
        OpenConsole();
        Log("LunaAG-Patch InitLevel=2 loaded");
        Log("module path: %s", WideToUtf8(GetModulePath(g_module)).c_str());
        Log("config dir: %s", WideToUtf8(g_moduleDir).c_str());
        return;
    }

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

    if (g_patchImports)
    {
        Log("stage: patch imports begin");
        PatchAllModules();
        Log("stage: patch imports end");
    }
    else
    {
        Log("patch imports disabled");
    }

    Log("initialized, enabled=%d rules=%zu", g_enabled ? 1 : 0, g_rules.size());
}

DWORD WINAPI InitThread(void*)
{
    Sleep(1000);

    const std::wstring moduleDir = GetModuleDirectory(g_module);
    const std::wstring iniPath = moduleDir + L"\\LunaAG-Patch.ini";
    if (GetPrivateProfileIntW(L"Redirect", L"SafeMode", 1, iniPath.c_str()) != 0)
    {
        AllocConsole();
        FILE* unused = nullptr;
        freopen_s(&unused, "CONOUT$", "w", stdout);
        freopen_s(&unused, "CONOUT$", "w", stderr);
        SetConsoleTitleW(L"LunaAG-Patch");
        std::printf("LunaAG-Patch SafeMode loaded\n");
        std::fflush(stdout);

        while (true)
        {
            Sleep(1000);
        }
    }

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
            if (g_patchImports)
            {
                if (now - g_lastPatchTick >= 1000)
                {
                    g_lastPatchTick = now;
                    PatchAllModules();
                }
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
        Initialize();
    }
    catch (...)
    {
        Log("fatal: C++ exception during InstallRedirectHooks");
    }
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        g_module = module;
        DisableThreadLibraryCalls(module);
        HANDLE thread = CreateThread(nullptr, 0, &InitThread, nullptr, 0, nullptr);
        if (thread)
        {
            CloseHandle(thread);
        }
    }

    return TRUE;
}
