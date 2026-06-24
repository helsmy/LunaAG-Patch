#pragma once

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

namespace LunaAGPatch
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

inline constexpr size_t kInvalidOffset = static_cast<size_t>(-1);

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

struct InlineHook
{
    void* target = nullptr;
    void* replacement = nullptr;
    void* trampoline = nullptr;
    uint8_t original[16]{};
    size_t patchSize = 12;
    bool installed = false;
};

inline constexpr GUID kWsaIdConnectEx = {
    0x25a207b9,
    0xddf3,
    0x4660,
    {0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e}
};

extern HMODULE g_module;
extern HMODULE g_pinnedModule;
extern std::wstring g_moduleDir;
extern std::wstring g_logPath;
extern std::wstring g_windowsDir;
extern std::vector<RedirectRule> g_rules;
extern std::vector<ResolvedHost> g_resolvedHosts;
extern std::unordered_map<HINTERNET, std::wstring> g_winHttpRequestPaths;
extern std::unordered_set<void*> g_patchedLoginModules;
extern std::mutex g_mutex;
extern std::recursive_mutex g_inlineHookMutex;
extern bool g_enabled;
extern bool g_logEnabled;
extern bool g_consoleEnabled;
extern bool g_consoleReady;
extern bool g_patchImports;
extern bool g_logAllConnects;
extern bool g_logAllDns;
extern bool g_patchAllNonSystem;
extern bool g_keepAlive;
extern bool g_uiPatch;
extern bool g_forceLoginCallback;
extern bool g_inlineHooks;
extern bool g_initialized;
extern bool g_logCleared;
extern DWORD g_lastPatchTick;
extern DWORD g_lastUiPatchTick;
extern std::wstring g_captchaFlagPath;
extern std::wstring g_forceLoginFlagPath;
extern ConnectFn g_connect;
extern WsaConnectFn g_wsaConnect;
extern WsaIoctlFn g_wsaIoctl;
extern ConnectExFn g_connectEx;
extern GetAddrInfoFn g_getaddrinfo;
extern GetAddrInfoWFn g_getaddrinfoW;
extern GetProcAddressFn g_getProcAddress;
extern WinHttpConnectFn g_winHttpConnect;
extern WinHttpOpenRequestFn g_winHttpOpenRequest;
extern WinHttpSendRequestFn g_winHttpSendRequest;
extern Il2CppDomainGetFn g_il2cppDomainGet;
extern Il2CppThreadAttachFn g_il2cppThreadAttach;
extern Il2CppDomainGetAssembliesFn g_il2cppDomainGetAssemblies;
extern Il2CppAssemblyGetImageFn g_il2cppAssemblyGetImage;
extern Il2CppClassFromNameFn g_il2cppClassFromName;
extern Il2CppClassGetTypeFn g_il2cppClassGetType;
extern Il2CppTypeGetObjectFn g_il2cppTypeGetObject;
extern Il2CppClassGetMethodFromNameFn g_il2cppClassGetMethodFromName;
extern Il2CppClassGetFieldFromNameFn g_il2cppClassGetFieldFromName;
extern Il2CppFieldGetOffsetFn g_il2cppFieldGetOffset;
extern Il2CppRuntimeInvokeFn g_il2cppRuntimeInvoke;
extern Il2CppStringNewFn g_il2cppStringNew;
extern Il2CppArrayLengthFn g_il2cppArrayLength;
extern Il2CppObjectNewFn g_il2cppObjectNew;
extern void* g_loginModuleClass;
extern void* g_unityObjectClass;
extern void* g_inputFieldClass;
extern void* g_loginResultClass;
extern void* g_userInfoClass;
extern void* g_logoffApplyClass;
extern void* g_findObjectsOfTypeMethod;
extern void* g_textSetTextMethod;
extern void* g_geetestVerifyCallbackMethod;
extern void* g_innerLoginCallbackMethod;
extern void* g_loginResultCtorMethod;
extern void* g_userInfoCtorMethod;
extern void* g_logoffApplyCtorMethod;
extern bool g_pendingCaptchaBypass;
extern bool g_pendingForceLoginCallback;
extern bool g_forceLoginCallbackDone;
extern Il2CppFieldOffsets g_offsets;
extern bool g_offsetsResolved;
extern InlineHook g_connectInlineHook;
extern InlineHook g_wsaConnectInlineHook;
extern InlineHook g_wsaIoctlInlineHook;

std::string ToLower(std::string value);
std::string WideToUtf8(const std::wstring& value);
std::wstring Utf8ToWide(const std::string& value);
bool ReplaceAll(std::string& value, const std::string& from, const std::string& to);
template <typename T>
T Proc(HMODULE module, const char* name)
{
    return reinterpret_cast<T>(GetProcAddress(module, name));
}
void Log(const char* format, ...);
bool WriteAbsoluteJump(void* address, void* destination, uint8_t* savedBytes = nullptr);
bool InstallInlineHook(InlineHook& hook, void* target, void* replacement, void** original, const char* name);
bool RestoreInlineHook(InlineHook& hook);
bool ReapplyInlineHook(InlineHook& hook);
void ClearLogFile();
void OpenConsole();
std::wstring GetModuleDirectory(HMODULE module);
std::wstring GetModulePath(HMODULE module);
std::wstring ToLowerWide(std::wstring value);
bool StartsWith(const std::wstring& value, const std::wstring& prefix);
bool IsPatchTargetModule(HMODULE module);
void* FindIl2CppClass(const char* namespaze, const char* name);
size_t FieldOffset(void* klass, const char* fieldName, size_t fallback);
size_t BackingFieldOffset(void* klass, const char* propertyName, size_t fallback);
bool HasOffset(size_t offset);
void SetObjectField(void* object, size_t offset, void* value);
void SetStringField(void* object, size_t offset, const char* value);
void SetI64Field(void* object, size_t offset, int64_t value);
void SetI32Field(void* object, size_t offset, int32_t value);
void SetBoolField(void* object, size_t offset, bool value);
bool ResolveIl2CppFieldOffsets();
bool ResolveIl2CppUiPatch();
void SetUnityText(void* textObject, const char* value);
void PatchLoginModuleObject(void* loginModule);
bool BypassCaptchaForLoginModule(void* loginModule);
bool InvokeDefaultCtor(void* object, void* ctorMethod, const char* name);
void* CreateLocalLoginResult();
bool ForceLoginSuccessForLoginModule(void* loginModule);
bool ConsumeCaptchaBypassFlag();
bool ConsumeForceLoginFlag();
void ClearPendingSignalFlags();
void PatchLoginModules();
std::string ReadIniString(const wchar_t* section, const wchar_t* key, const wchar_t* fallback);
int ReadIniInt(const wchar_t* section, const wchar_t* key, int fallback);
bool ParseIpv4(const std::string& host, uint32_t& output);
uint16_t Swap16(uint16_t value);
std::string Ipv4ToString(uint32_t address);
void LogSockaddr(const char* api, const sockaddr* name);
void LoadConfig();
void RememberResolvedHost(const RedirectRule& rule);
RedirectRule* FindRule(const sockaddr* name);
bool RewriteSockaddr(const sockaddr* input, int inputLength, sockaddr_storage& storage, int& storageLength);
int CallOriginalConnect(SOCKET socket, const sockaddr* name, int namelen);
int CallOriginalWsaConnect(SOCKET socket, const sockaddr* name, int namelen, LPWSABUF callerData, LPWSABUF calleeData, LPQOS sqos, LPQOS gqos);
int CallOriginalWsaIoctl(SOCKET socket, DWORD ioControlCode, LPVOID inBuffer, DWORD inBufferSize, LPVOID outBuffer, DWORD outBufferSize, LPDWORD bytesReturned, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine);
int WSAAPI HookConnect(SOCKET socket, const sockaddr* name, int namelen);
int WSAAPI HookWsaConnect(SOCKET socket, const sockaddr* name, int namelen, LPWSABUF callerData, LPWSABUF calleeData, LPQOS sqos, LPQOS gqos);
BOOL PASCAL HookConnectEx(SOCKET socket, const sockaddr* name, int namelen, PVOID sendBuffer, DWORD sendDataLength, LPDWORD bytesSent, LPOVERLAPPED overlapped);
int WSAAPI HookWsaIoctl(SOCKET socket, DWORD ioControlCode, LPVOID inBuffer, DWORD inBufferSize, LPVOID outBuffer, DWORD outBufferSize, LPDWORD bytesReturned, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine);
RedirectRule* FindHostnameRule(const std::string& node);
RedirectRule* FindHostnamePortRule(const std::string& node, uint16_t port);
HINTERNET WINAPI HookWinHttpConnect(HINTERNET session, LPCWSTR serverName, INTERNET_PORT serverPort, DWORD reserved);
HINTERNET WINAPI HookWinHttpOpenRequest(HINTERNET connect, LPCWSTR verb, LPCWSTR objectName, LPCWSTR version, LPCWSTR referrer, LPCWSTR* acceptTypes, DWORD flags);
BOOL WINAPI HookWinHttpSendRequest(HINTERNET request, LPCWSTR headers, DWORD headersLength, LPVOID optional, DWORD optionalLength, DWORD totalLength, DWORD_PTR context);
int WSAAPI HookGetAddrInfo(PCSTR node, PCSTR service, const ADDRINFOA* hints, PADDRINFOA* result);
int WSAAPI HookGetAddrInfoW(PCWSTR node, PCWSTR service, const ADDRINFOW* hints, PADDRINFOW* result);
FARPROC WINAPI HookGetProcAddress(HMODULE module, LPCSTR procName);
bool IsReadablePeImage(HMODULE module);
bool IsSystemModule(HMODULE module);
int PatchImport(HMODULE module, const char* importedModule, const char* functionName, void* replacement, void** original);
void PatchModule(HMODULE module);
void PatchAllModules();
void InstallInlineHooks();
void Initialize();
DWORD WINAPI InitThread(void*);
}
