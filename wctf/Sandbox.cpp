#include "Sandbox.h"

namespace common {
	void Sid::from_pointer(void * ptr) {
		auto stream = new BinaryStream(ptr, 0xffff);

		auto revision = stream->read<uint8_t>();
		if (revision != 1) {
			throw std::exception("Invalid SID pointer");
		}
		auto subauth_cnt = stream->read<uint8_t>();
		for (auto i = 0; i < 6; i++) {
			m_sia.Value[i] = stream->read<uint8_t>();
		}
		for (auto i = 0; i < subauth_cnt; i++) {
			m_subauth.push_back(stream->read<uint32_t>());
		}
	}

#pragma warning(disable:4267)
	std::unique_ptr<BinaryStream> Sid::as_stream() {
		auto stream = std::make_unique<BinaryStream>(1032);
		stream->write<uint8_t>(1);
		stream->write<uint8_t>(m_subauth.size());
		for (auto i = 0; i < 6; i++) {
			stream->write<uint8_t>(m_sia.Value[i]);
		}
		for (auto i = 0; i < m_subauth.size(); i++) {
			stream->write<uint32_t>(m_subauth[i]);
		}
		return std::move(stream);
	}
#pragma warning(default:4267)

	std::unique_ptr<std::string> Sid::repr() {
		auto stream = as_stream();
		char* stringsid = nullptr;
		if (!::ConvertSidToStringSidA(stream->pointer(), &stringsid)) {
			throw std::exception("Invalid SID");
		}
		auto result = std::make_unique<std::string>(stringsid);
		::LocalFree(stringsid);
		return std::move(result);
	}

	HANDLE FilteredToken::make() {
#pragma warning(disable:4267)
		HANDLE result = nullptr, 
			current;
		PSID_AND_ATTRIBUTES disabled = nullptr, restricted = nullptr;
		PLUID_AND_ATTRIBUTES privileges = nullptr;
		DWORD priv_cnt = 0, disabled_cnt = 0, restricted_cnt = 0;

		if(!m_token) {
			if (!::OpenProcessToken(
				::GetCurrentProcess(),
				TOKEN_ALL_ACCESS,
				&current
			)) {
				throw std::exception("OpenProcessToken failed");
			}
		}
		else {
			current = m_token;
		}
		SandboxLauncher::disable_inherit(result);

		if (m_privilege.size()) {
			privileges = new LUID_AND_ATTRIBUTES[m_privilege.size()];
			auto index = 0;
			std::for_each(m_privilege.begin(), m_privilege.end(), [&index, privileges](std::unique_ptr<std::string>& priv) {
				if (!::LookupPrivilegeValueA(nullptr, priv->c_str(), &privileges[index].Luid)) {
					throw std::exception("Failed lookup privilege");
				}
				privileges[index].Attributes = 0;
				index++;
			});
			priv_cnt = m_privilege.size();
		}

		std::vector<std::unique_ptr<BinaryStream>> disabled_ptr;
		if (m_disabled.size()) {
			disabled = new SID_AND_ATTRIBUTES[m_disabled.size()];
			std::for_each(m_disabled.begin(), m_disabled.end(), [&disabled_ptr](std::unique_ptr<Sid>& sid) {
				disabled_ptr.push_back(std::move(sid->as_stream()));
			});
			for (auto i = 0; i < m_disabled.size(); i++) {
				disabled[i].Sid = disabled_ptr[i]->pointer();
				disabled[i].Attributes = 0;
			}
			disabled_cnt = m_disabled.size();
		}

		std::vector<std::unique_ptr<BinaryStream>> restricted_ptr;
		if (m_restricted.size()) {
			restricted = new SID_AND_ATTRIBUTES[m_restricted.size()];
			std::for_each(m_restricted.begin(), m_restricted.end(), [&restricted_ptr](std::unique_ptr<Sid>& sid) {
				restricted_ptr.push_back(std::move(sid->as_stream()));
			});
			for (auto i = 0; i < m_restricted.size(); i++) {
				restricted[i].Sid = restricted_ptr[i]->pointer();
				restricted[i].Attributes = 0;
			}
			restricted_cnt = m_restricted.size();
		}

		if (!::CreateRestrictedToken(
			current,
			m_flags,
			disabled_cnt,
			disabled,
			priv_cnt,
			privileges,
			restricted_cnt,
			restricted,
			&result
		)) {
			throw std::exception("Failed create filtered token");
		}

		if (privileges) delete[] privileges;
		if (disabled) delete[] disabled;
		if (restricted) delete[] restricted;
		SandboxLauncher::disable_inherit(result);

		return result;
#pragma warning(default:4267)
	}

	HANDLE LowBoxToken::make() {
		HANDLE result = nullptr, 
			current;
		
		if (!m_token) {
			if (!::OpenProcessToken(
				::GetCurrentProcess(),
				TOKEN_ALL_ACCESS,
				&current
			)) {
				throw std::exception("OpenProcessToken failed");
			}
			m_token = current;
		}
		else {
			current = m_token;
		}
		SandboxLauncher::disable_inherit(m_token);

		auto package = m_package->as_stream();

		PSID_AND_ATTRIBUTES capabilities = nullptr;
		std::vector<std::unique_ptr<BinaryStream>> capability_sids;
		if (!m_capabilities.empty()) {
			capabilities = new SID_AND_ATTRIBUTES[m_capabilities.size()];
			std::for_each(m_capabilities.begin(), m_capabilities.end(), [&capability_sids](const std::unique_ptr<Sid>& val) {
				capability_sids.push_back(std::move(val->as_stream()));
			});
			for (auto i = 0; i < capability_sids.size(); i++) {
				capabilities[i].Sid = capability_sids[i]->pointer();
				capabilities[i].Attributes = SE_GROUP_ENABLED;
			}
		}

		PHANDLE handles = nullptr;
		if (!m_handles.empty()) {
			handles = new HANDLE[m_handles.size()];
			for (auto i = 0; i < m_handles.size(); i++) {
				handles[i] = m_handles[i];
			}
		}

#pragma warning(disable:4267)
		auto status = ::NtCreateLowBoxToken(
			&result,
			current,
			TOKEN_ALL_ACCESS,
			nullptr,
			package->pointer(),
			m_capabilities.size(),
			capabilities,
			m_handles.size(),
			handles
		);
#pragma warning(default:4267)

		if (capabilities != nullptr) delete[] capabilities;
		if (handles != nullptr) delete[] handles;
		
		if (!NT_SUCCESS(status)) {
			throw std::exception("NtCreateLowBoxToken failed");
		}

		SandboxLauncher::disable_inherit(result);
		return result;
	}

	bool SandboxLauncher::disable_inherit(HANDLE h, bool disable) {
		if (::SetHandleInformation(h, HANDLE_FLAG_INHERIT, disable ? 0 : 1)) {
			return true;
		}
		return false;
	}

	bool SandboxLauncher::enable_mitigation() {
		// looks like ProcessMitigationPolicy can be changed only by the calling process
//		PROCESS_MITIGATION_POLICY_INFORMATION pmpi;
//
//#define SET_MITIGATION(v,f) \
//		pmpi.Policy = Process##v; \
//		pmpi.v.Flags = f; \
//		do { NTSTATUS s; if(!NT_SUCCESS((s = ::NtSetInformationProcess(::GetCurrentProcess(), ProcessMitigationPolicy, &pmpi, sizeof(pmpi))))) { std::cout << #v << ' ' << s << std::endl; return false; } } while(0);
//
//		SET_MITIGATION(ASLRPolicy, 7);
//		SET_MITIGATION(StrictHandleCheckPolicy, 1);
//		SET_MITIGATION(SystemCallDisablePolicy, 1);
//		SET_MITIGATION(ExtensionPointDisablePolicy, 1);
//		SET_MITIGATION(FontDisablePolicy, 1);
//		SET_MITIGATION(ImageLoadPolicy, 7);
//
//#undef SET_MITIGATION

		//do {
		//	PROCESS_MITIGATION_DEP_POLICY dep;
		//	::RtlZeroMemory(&dep, sizeof(dep));
		//	dep.Enable = 1;
		//	dep.DisableAtlThunkEmulation = 1;
		//	dep.Permanent = 1;
		//	if (!::SetProcessMitigationPolicy(ProcessDEPPolicy, &dep, sizeof(dep))) {
		//		printf("dep %d\n", ::GetLastError());
		//		return false;
		//	}
		//} while (0);

		//do {
		//	PROCESS_MITIGATION_ASLR_POLICY aslr;
		//	::RtlZeroMemory(&aslr, sizeof(aslr));
		//	aslr.EnableHighEntropy = 1;
		//	aslr.EnableForceRelocateImages = 1;
		//	aslr.EnableBottomUpRandomization = 1;
		//	if (!::SetProcessMitigationPolicy(ProcessASLRPolicy, &aslr, sizeof(aslr))) {
		//		printf("aslr %d\n", ::GetLastError());
		//		return false;
		//	}
		//} while (0);

		do {
			PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY sh;
			::RtlZeroMemory(&sh, sizeof(sh));
			sh.RaiseExceptionOnInvalidHandleReference = 1;
			sh.HandleExceptionsPermanentlyEnabled = 1;
			if (!::SetProcessMitigationPolicy(ProcessStrictHandleCheckPolicy, &sh, sizeof(sh))) {
				return false;
			}
		} while (0);

		do {
			PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY win32k;
			::RtlZeroMemory(&win32k, sizeof(win32k));
			win32k.DisallowWin32kSystemCalls = 1;
			if (!::SetProcessMitigationPolicy(ProcessSystemCallDisablePolicy, &win32k, sizeof(win32k))) {
				return false;
			}
		} while (0);

		do {
			PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ep;
			::RtlZeroMemory(&ep, sizeof(ep));
			ep.DisableExtensionPoints = 1;
			if (!::SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, &ep, sizeof(ep))) {
				return false;
			}
		} while (0);

		do {
			PROCESS_MITIGATION_FONT_DISABLE_POLICY font;
			::RtlZeroMemory(&font, sizeof(font));
			font.DisableNonSystemFonts = 1;
			if (!::SetProcessMitigationPolicy(ProcessFontDisablePolicy, &font, sizeof(font))) {
				return false;
			}
		} while (0);

		do {
			PROCESS_MITIGATION_IMAGE_LOAD_POLICY image;
			::RtlZeroMemory(&image, sizeof(image));
			image.NoLowMandatoryLabelImages = image.NoRemoteImages = image.PreferSystem32Images = 1;
			if (!::SetProcessMitigationPolicy(ProcessImageLoadPolicy, &image, sizeof(image))) {
				return false;
			}
		} while (0);

		return true;
	}
	
	bool SandboxLauncher::lockdown() {
		TOKEN_MANDATORY_LABEL tml;
		PSID sid = nullptr;
		HANDLE hCurrent = nullptr;
		bool ret = false;

		if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ALL_ACCESS, &hCurrent)) {
			goto bailout;
		}

		if (!::ConvertStringSidToSidA("S-1-16-0", &sid)) {
			goto bailout;
		}
		tml.Label.Sid = sid;
		tml.Label.Attributes = SE_GROUP_INTEGRITY;

		if (!::SetTokenInformation(hCurrent, TokenIntegrityLevel, &tml, sizeof(tml))) {
			goto bailout;
		}

		ret = true;

	bailout:

		if (hCurrent) ::CloseHandle(hCurrent);
		if (sid) ::LocalFree(sid);

		return ret;
	}

	PROCESS_INFORMATION SandboxLauncher::launch(PreLaunchCallback prelaunch, PostLaunchCallback postlaunch) {
		LPPROC_THREAD_ATTRIBUTE_LIST pptal = nullptr;
		SIZE_T dwSize = 0;
		HANDLE hProcess = nullptr;
		HANDLE hJob = nullptr;
		HANDLE hToken = nullptr;
		STARTUPINFOEXA si;
		PROCESS_INFORMATION pi;

		::RtlZeroMemory(&pi, sizeof(pi));

		/* Craft ps attributes */
		if (::InitializeProcThreadAttributeList(pptal, 2, 0, &dwSize) != 0 || ::GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			goto bailout;
		}
		pptal = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(halloc(dwSize));
		if (!::InitializeProcThreadAttributeList(pptal, 2, 0, &dwSize)) {
			goto bailout;
		}
		
		if(!::UpdateProcThreadAttribute(pptal, 0, PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, &m_childpolicy, sizeof(m_childpolicy), NULL, NULL)) {
			goto bailout;
		}

		if (m_mitigation && !::UpdateProcThreadAttribute(pptal, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &m_mitigation, sizeof(m_mitigation), NULL, NULL)) {
			goto bailout;
		}

		/* Craft job object */
		hJob = ::CreateJobObjectA(nullptr, nullptr);
		disable_inherit(hJob);
		if (!hJob) {
			goto bailout;
		}
		
		if (m_restrictui) {
			JOBOBJECT_BASIC_UI_RESTRICTIONS jbur;
			::RtlZeroMemory(&jbur, sizeof(jbur));
			jbur.UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP;
			jbur.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_DISPLAYSETTINGS;
			jbur.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_EXITWINDOWS;
			jbur.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_GLOBALATOMS;
			jbur.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_HANDLES;
			jbur.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_READCLIPBOARD;
			jbur.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS;
			jbur.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
			if (!::SetInformationJobObject(hJob, JobObjectBasicUIRestrictions, &jbur, sizeof(jbur))) {
				goto bailout;
			}
		}
		do {
			JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli;
			ZeroMemory(&jeli, sizeof(jeli));
			jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
			jeli.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart = m_timeout;
			jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
			jeli.ProcessMemoryLimit = m_memlimit;
			jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
			jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
			jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
			jeli.BasicLimitInformation.ActiveProcessLimit = 1;
			if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli))) {
				goto bailout;
			}
		} while (0);

		/* Craft token */
		if (m_token) {
			hToken = m_token;
		}
		else {
			if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
				goto bailout;
			}
			m_token = hToken;
		}
		disable_inherit(m_token);

		/* Craft parameters */
		::RtlZeroMemory(&si, sizeof(si));
		si.StartupInfo.cb = sizeof(si);
		si.lpAttributeList = pptal;
		if (m_stdin && m_stdout && m_stderr) {
			si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
			si.StartupInfo.hStdInput = m_stdin;
			si.StartupInfo.hStdOutput = m_stdout;
			si.StartupInfo.hStdError = m_stderr;
		}

		prelaunch(si);

		if (!::CreateProcessAsUserA(
			hToken, 
			m_executable->c_str(), 
			const_cast<LPSTR>(m_application->c_str()), 
			nullptr, 
			nullptr, 
			TRUE, 
			CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, 
			nullptr, 
			nullptr, 
			&si.StartupInfo,
			&pi
		)) {
			//printf("%s %d\n", __FUNCTION__, ::GetLastError());
			goto bailout;
		}

		if (!::AssignProcessToJobObject(hJob, pi.hProcess)) {
			::TerminateProcess(pi.hProcess, 255);
			goto bailout;
		}

		postlaunch(pi, hJob);

	bailout:
		if (pptal) hfree(pptal);
		if (hToken) ::CloseHandle(hToken);
		return pi;
	}
}