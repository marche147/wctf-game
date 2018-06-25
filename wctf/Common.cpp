#include "Common.h"

namespace common {
	DWORD Win32FromHResult(HRESULT hr) {
		/* https://stackoverflow.com/questions/22233527/how-to-convert-hresult-into-an-error-description */
		if ((hr & 0xFFFF0000) == MAKE_HRESULT(SEVERITY_ERROR, FACILITY_WIN32, 0)) {
			return HRESULT_CODE(hr);
		}
		if (hr == S_OK) {
			return ERROR_SUCCESS;
		}
		// Not a Win32 HRESULT so return a generic error code.
		return ERROR_CAN_NOT_COMPLETE;
	}

	//std::unique_ptr<std::string> RelativePathToAbsolute(const char* path) {
	//	if (::PathIsRelativeA(path)) {
	//		char pathBuffer[MAX_PATH];
	//		CHECK_NONZERO(::GetCurrentDirectoryA(sizeof(pathBuffer), pathBuffer));
	//		CHECK_HRESULT(::StringCbCatA(pathBuffer, sizeof(pathBuffer), path));
	//		return std::move(std::make_unique<std::string>(pathBuffer));
	//	}
	//	return std::move(std::make_unique<std::string>(path));
	//}

	std::unique_ptr<std::string> Win32ErrToString(DWORD err) {
		char* msgBuf = nullptr;

		CHECK_NONZERO(::FormatMessageA(
			FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			err,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR)&msgBuf,
			0, NULL
		));
		std::unique_ptr<std::string> result = std::make_unique<std::string>(msgBuf);
		LocalFree(msgBuf);

		return std::move(result);
	}

	DWORD fork(void) {
		RTL_USER_PROCESS_INFORMATION proc_info;
		NTSTATUS s;
		DWORD ret;

		s = ::RtlCloneUserProcess(RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED | RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES, NULL, NULL, NULL, &proc_info);
		if (!NT_SUCCESS(s)) {
			return -1;
		} else if (s == STATUS_PROCESS_CLONED) {	// child
			return 0;
		}
		ret = ::GetProcessId(proc_info.Process);
		::ResumeThread(proc_info.Thread);
		::CloseHandle(proc_info.Process);
		::CloseHandle(proc_info.Thread);
		return ret;
	}

	std::unique_ptr<std::string> GetProcessPath(void) {
		char buffer[MAX_PATH];
		CHECK_NONZERO(::GetModuleFileNameA(NULL, buffer, MAX_PATH));
		return std::move(std::make_unique<std::string>(buffer));
	}

	// https://github.com/aurel26/s-4-u-for-windows
	BOOL
		GetLogonSID(
			_In_ HANDLE hToken,
			_Out_ PSID *pLogonSid
		)
	{
		BOOL bSuccess = FALSE;
		DWORD dwIndex;
		DWORD dwLength = 0;
		PTOKEN_GROUPS pTokenGroups = NULL;

		//
		// Get required buffer size and allocate the TOKEN_GROUPS buffer.
		//
		if (!GetTokenInformation(
			hToken,
			TokenGroups,
			(LPVOID)pTokenGroups,
			0,
			&dwLength
		))
		{
			if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			{
				goto Error;
			}

			pTokenGroups = (PTOKEN_GROUPS)HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);
			if (pTokenGroups == NULL)
				goto Error;
		}

		//
		// Get the token group information from the access token.
		//
		if (!GetTokenInformation(
			hToken,
			TokenGroups,
			(LPVOID)pTokenGroups,
			dwLength,
			&dwLength
		))
		{
			fprintf(stderr, "GetTokenInformation failed (error: %u).\n", GetLastError());
			goto Error;
		}

		//
		// Loop through the groups to find the logon SID.
		//
		for (dwIndex = 0; dwIndex < pTokenGroups->GroupCount; dwIndex++)
			if ((pTokenGroups->Groups[dwIndex].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
			{
				//
				// Found the logon SID: make a copy of it.
				//
				dwLength = GetLengthSid(pTokenGroups->Groups[dwIndex].Sid);
				*pLogonSid = (PSID)HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);
				if (*pLogonSid == NULL)
					goto Error;
				if (!CopySid(dwLength, *pLogonSid, pTokenGroups->Groups[dwIndex].Sid))
				{
					goto Error;
				}
				break;
			}

		bSuccess = TRUE;

	Error:
		if (bSuccess == FALSE)
		{
			if (*pLogonSid != NULL)
				HeapFree(::GetProcessHeap(), 0, *pLogonSid);
		}

		if (pTokenGroups != NULL)
			HeapFree(::GetProcessHeap(), 0, pTokenGroups);

		return bSuccess;
	}

	VOID
		InitLsaString(
			_Out_ PLSA_STRING DestinationString,
			_In_z_ LPSTR szSourceString
		)
	{
		USHORT StringSize;

		StringSize = (USHORT)strlen(szSourceString);

		DestinationString->Length = StringSize;
		DestinationString->MaximumLength = StringSize + sizeof(CHAR);
		DestinationString->Buffer = (PCHAR)HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, DestinationString->MaximumLength);

		if (DestinationString->Buffer)
		{
			memcpy(DestinationString->Buffer, szSourceString, DestinationString->Length);
		}
		else
		{
			memset(DestinationString, 0, sizeof(LSA_STRING));
		}
	}

	PBYTE
		InitUnicodeString(
			_Out_ PUNICODE_STRING DestinationString,
			_In_z_ LPWSTR szSourceString,
			_In_ PBYTE pbDestinationBuffer
		)
	{
		USHORT StringSize;

		StringSize = (USHORT)wcslen(szSourceString) * sizeof(WCHAR);
		memcpy(pbDestinationBuffer, szSourceString, StringSize);

		DestinationString->Length = StringSize;
		DestinationString->MaximumLength = StringSize + sizeof(WCHAR);
		DestinationString->Buffer = (PWSTR)pbDestinationBuffer;

		return (PBYTE)pbDestinationBuffer + StringSize + sizeof(WCHAR);
	}

	HANDLE LogonS4U(const wchar_t* user, const wchar_t* realm, NTSTATUS* rets) {
		LSA_HANDLE lsa = nullptr;
		NTSTATUS status = 0xc0000001, SubStatus;
		HANDLE hToken = nullptr, current = nullptr;
		LSA_STRING Msv1_0Name = { 0 };
		LSA_STRING OriginName = { 0 };
		PMSV1_0_S4U_LOGON pS4uLogon = NULL;
		TOKEN_SOURCE TokenSource;
		ULONG ulAuthenticationPackage;
		DWORD dwMessageLength;
		PSID pLogonSid = NULL;
		PVOID pvProfile = NULL;
		DWORD dwProfile = 0;
		LUID logonId = { 0 };
		QUOTA_LIMITS quotaLimits;
		PTOKEN_GROUPS pGroups = NULL;
		PBYTE pbPosition;

		if (rets) *rets = 0;

		if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ALL_ACCESS, &current)) {
			goto bailout;
		}

		if (!GetLogonSID(current, &pLogonSid)) {
			goto bailout;
		}

		status = ::LsaConnectUntrusted(&lsa);
		if (!NT_SUCCESS(status)) {
			goto bailout;
		}

		InitLsaString(&Msv1_0Name, const_cast<LPSTR>(MSV1_0_PACKAGE_NAME));
		status = LsaLookupAuthenticationPackage(lsa, &Msv1_0Name, &ulAuthenticationPackage);
		if (!NT_SUCCESS(status)) {
			goto bailout;
		}

#define EXTRA_SID_COUNT          2
		dwMessageLength = (DWORD)sizeof(MSV1_0_S4U_LOGON) + (EXTRA_SID_COUNT + (DWORD)wcslen(realm) + (DWORD)wcslen(user)) * sizeof(WCHAR);
		pS4uLogon = (PMSV1_0_S4U_LOGON)HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, dwMessageLength);
		if (pS4uLogon == NULL) {
			goto bailout;
		}
		pS4uLogon->MessageType = MsV1_0S4ULogon;
		pbPosition = (PBYTE)pS4uLogon + sizeof(MSV1_0_S4U_LOGON);
		pbPosition = InitUnicodeString(&pS4uLogon->UserPrincipalName, const_cast<LPWSTR>(user), pbPosition);
		pbPosition = InitUnicodeString(&pS4uLogon->DomainName, const_cast<LPWSTR>(realm), pbPosition);

		strcpy_s(TokenSource.SourceName, TOKEN_SOURCE_LENGTH, "S4UWin");
		InitLsaString(&OriginName, const_cast<LPSTR>("S4U for Windows"));
		AllocateLocallyUniqueId(&TokenSource.SourceIdentifier);

		pGroups = (PTOKEN_GROUPS)HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TOKEN_GROUPS) + 2 * sizeof(SID_AND_ATTRIBUTES));
		if (pLogonSid) {
			pGroups->Groups[pGroups->GroupCount].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
			pGroups->Groups[pGroups->GroupCount].Sid = pLogonSid;
			pGroups->GroupCount++;
		}

		status = LsaLogonUser(
			lsa,
			&OriginName,
			Network,                // Or Batch
			ulAuthenticationPackage,
			pS4uLogon,
			dwMessageLength,
			pGroups,                // this requires privilege
			&TokenSource,           // SourceContext
			&pvProfile,
			&dwProfile,
			&logonId,
			&hToken,
			&quotaLimits,
			&SubStatus
		);

	bailout:

		if (current) ::CloseHandle(current);
		if (pLogonSid) ::HeapFree(::GetProcessHeap(), 0, pLogonSid);
		if (pGroups) ::HeapFree(::GetProcessHeap(), 0, pGroups);
		if (pS4uLogon) ::HeapFree(::GetProcessHeap(), 0, pS4uLogon);
		if (rets) *rets = status;
		if (lsa) ::LsaClose(lsa);
		return hToken;
	}

	bool EnablePrivilege(const char* priv) {
		HANDLE hCurrent = nullptr;
		bool ret = false;
		PTOKEN_PRIVILEGES privs = nullptr;
		uintptr_t length = sizeof(TOKEN_PRIVILEGES) + (1 - 1) * sizeof(LUID_AND_ATTRIBUTES);

		if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ALL_ACCESS, &hCurrent)) {
			goto bailout;
		}

		privs = reinterpret_cast<PTOKEN_PRIVILEGES>(halloc(length));
		privs->PrivilegeCount = 1;
		if (!::LookupPrivilegeValueA(nullptr, priv, &privs->Privileges[0].Luid)) {
			goto bailout;
		}
		privs->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
#pragma warning(disable:4244)
		if (!::AdjustTokenPrivileges(hCurrent, FALSE, privs, length, nullptr, 0)) {
			goto bailout;
		}
#pragma warning(default:4244)
		ret = true;

	bailout:
		if (hCurrent) ::CloseHandle(hCurrent);
		if (privs) hfree(privs);
		return ret;
	}

#pragma warning(disable:4267)
	bool SetMountPoint(HANDLE hDirectory, std::string& reparse) {
		std::string r = "\\??\\" + reparse;
		std::wstring redir(r.begin(), r.end());
		PREPARSE_DATA_BUFFER buffer = nullptr;
		DWORD retlen;
		DWORD size = 16 + sizeof(wchar_t) * redir.size() + 4;

		buffer = reinterpret_cast<PREPARSE_DATA_BUFFER>(halloc(size));
		buffer->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
		buffer->ReparseDataLength = 8 + sizeof(wchar_t) * redir.size() + 4;
		buffer->MountPointReparseBuffer.SubstituteNameOffset = 0;
		buffer->MountPointReparseBuffer.SubstituteNameLength = redir.size() * 2;
		buffer->MountPointReparseBuffer.PrintNameOffset = redir.size() * 2 + 2;
		buffer->MountPointReparseBuffer.PrintNameLength = 0;
		::RtlCopyMemory(buffer->MountPointReparseBuffer.PathBuffer, redir.c_str(), redir.size() * 2);

		if (!::DeviceIoControl(hDirectory, FSCTL_SET_REPARSE_POINT, buffer, size, nullptr, 0, &retlen, nullptr)) {
			return false;
		}
		return true;
	}
#pragma warning(default:4267)

	bool QueryRegValueDword(HKEY hKey, const char* valueName, uint32_t* value) {
		DWORD type;
		bool ret = false;
		DWORD v = 0;
		DWORD size = sizeof(v);

		if (::RegQueryValueExA(hKey, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(&v), &size) != ERROR_SUCCESS) {
			goto bailout;
		}

		*value = v;
		ret = true;

	bailout:
		return ret;
	}
}