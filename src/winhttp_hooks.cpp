#include "patch_internal.hpp"

namespace LunaAGPatch
{
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
    const bool isPasswordLoginRequest = requestPath == L"/pass/user/login"
        || requestPath == L"/sdk-api/pass/user/login";
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

    if (isPasswordLoginRequest)
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_pendingHideLoginUi = true;
        Log("login UI hide pending path=%s", WideToUtf8(requestPath).c_str());
    }

    return g_winHttpSendRequest(request, headers, headersLength, requestOptional, requestOptionalLength, requestTotalLength, context);
}
}
