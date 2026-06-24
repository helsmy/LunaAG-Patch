#include "patch_internal.hpp"

namespace LunaAGPatch
{
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
}
