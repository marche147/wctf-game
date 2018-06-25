#pragma once

#include "Common.h"
#include <sddl.h>
#include "BinaryStream.h"

#define MITIGATION_ON(x) PROCESS_CREATION_MITIGATION_POLICY_##x##_ALWAYS_ON
#define MITIGATION_OFF(x) PROCESS_CREATION_MITIGATION_POLICY_##x##_ALWAYS_OFF

namespace common {
	class Sid {
	public:
		// Initialize from pointer
		Sid(void* ptr) {
			from_pointer(ptr);
		}

		// Initialize from String SID
		Sid(const char* s) {
			PSID pSid = nullptr;
			if (!::ConvertStringSidToSidA(s, &pSid)) {
				throw std::exception("Invalid String SID");
			}
			from_pointer(pSid);
			::LocalFree(pSid);
		}

		std::unique_ptr<BinaryStream> as_stream();
		std::unique_ptr<std::string> repr();

	private:
		void from_pointer(void* ptr);

		SID_IDENTIFIER_AUTHORITY m_sia;
		std::vector<uint32_t> m_subauth;
	};

	class IToken {
	public:
		virtual HANDLE make() = 0;
	};

	class FilteredToken : public IToken {
	public:
		FilteredToken() {
			m_flags = 0;
			m_token = nullptr;
		}

		~FilteredToken() {
			if (m_token) ::CloseHandle(m_token);
		}

		inline void with_flags(uint32_t flags) { m_flags = flags; }
		inline void disable_all_privileges(bool doit) {
			if (doit) m_flags |= DISABLE_MAX_PRIVILEGE;
			else m_flags &= ~(DISABLE_MAX_PRIVILEGE);
		}
		inline void add_removed_privilege(const char* priv) { m_privilege.push_back(std::make_unique<std::string>(priv)); }
		inline void add_disabled_sid(const char* stringsid) { m_disabled.push_back(std::make_unique<Sid>(stringsid)); }
		inline void add_restricted_sid(const char* stringsid) { m_restricted.push_back(std::make_unique<Sid>(stringsid)); }
		inline void add_disabled_sid(void* ptr) { m_disabled.push_back(std::make_unique<Sid>(ptr)); }
		inline void add_restricted_sid(void* ptr) { m_restricted.push_back(std::make_unique<Sid>(ptr)); }
		inline void with_token(HANDLE h) { clear_token(); m_token = h; }
		inline void with_token(IToken* ptr) { clear_token(); m_token = ptr->make(); }
		inline void clear_token() { if (m_token) { ::CloseHandle(m_token); } m_token = nullptr; }

		virtual HANDLE make();

	private:

		uint32_t m_flags;
		std::vector<std::unique_ptr<std::string>> m_privilege;
		std::vector<std::unique_ptr<Sid>> m_disabled;
		std::vector<std::unique_ptr<Sid>> m_restricted;
		HANDLE m_token;
	};

	class LowBoxToken : public IToken {
	public:
		LowBoxToken() {
			m_package = nullptr;
			m_token = nullptr;
		}
		
		~LowBoxToken() {
			if (m_token) ::CloseHandle(m_token);
		}

		inline void package_sid(const char* string_sid) { m_package = std::make_unique<Sid>(string_sid); }
		inline void package_sid(void* ptr) { m_package = std::make_unique<Sid>(ptr); }
		inline void add_capability(const char* string_sid) { m_capabilities.push_back(std::make_unique<Sid>(string_sid)); }
		inline void add_capability(void* ptr) { m_capabilities.push_back(std::make_unique<Sid>(ptr)); }
		inline void add_handle(HANDLE h) { m_handles.push_back(h); }
		inline void with_token(HANDLE token) { clear_token(); m_token = token; }
		inline void with_token(IToken* token) { clear_token(); m_token = token->make(); }
		inline void clear_token() { if (m_token) { ::CloseHandle(m_token); } m_token = nullptr; }

		virtual HANDLE make();

	private:
		std::unique_ptr<Sid> m_package;
		std::vector<std::unique_ptr<Sid>> m_capabilities;
		std::vector<HANDLE> m_handles;
		HANDLE m_token;
	};

	using PreLaunchCallback = void(STARTUPINFOEXA&);
	using PostLaunchCallback = void(PROCESS_INFORMATION&, HANDLE);

	class SandboxLauncher {
	public:
		SandboxLauncher() {
			m_restrictui = false;
			m_mitigation = 0;
			m_childpolicy = 0;
			m_memlimit = 0x10000000;
			m_timeout = 1200000000;
			m_stdin = m_stdout = m_stderr = nullptr;
			m_token = nullptr;
		}

		~SandboxLauncher() {
			if (m_token) ::CloseHandle(m_token);
		}

		inline void with_mitigation(uint64_t mitigation) { m_mitigation = mitigation; }
		inline void restrict_child(bool restricted) { m_childpolicy = restricted ? PROCESS_CREATION_CHILD_PROCESS_RESTRICTED : 0; }
		inline void restrict_ui_access(bool restricted) { m_restrictui = restricted; }
		inline void with_memory_limit(uintptr_t value) { m_memlimit = value; }
		inline void with_timeout(uintptr_t value) { m_timeout = value; }
		inline void command_line(const char* ptr) { m_application = std::make_unique<std::string>(ptr); }
		inline void command_line(std::unique_ptr<std::string> &ptr) { m_application = std::move(ptr); }
		inline void executable(const char* ptr) { m_executable = std::make_unique<std::string>(ptr); }
		inline void executable(std::unique_ptr<std::string> &ptr) { m_executable = std::move(ptr); }
		inline void with_stdio(HANDLE in, HANDLE out, HANDLE err) { m_stdin = in; m_stdout = out; m_stderr = err; };
		inline void with_token(IToken* token) { clear_token(); m_token = token->make(); }
		inline void clear_token() { if (m_token) { ::CloseHandle(m_token); } m_token = nullptr; }

		PROCESS_INFORMATION launch(PreLaunchCallback prelaunch, PostLaunchCallback postlaunch);

		static bool disable_inherit(HANDLE h, bool disable = true);
		static bool enable_mitigation();
		static bool lockdown();

	private:
		
		bool m_restrictui;
		uint64_t m_mitigation;
		uint32_t m_childpolicy;
		uintptr_t m_memlimit;
		uint64_t m_timeout;
		std::unique_ptr<std::string> m_application;
		std::unique_ptr<std::string> m_executable;
		HANDLE m_stdin, m_stdout, m_stderr;
		HANDLE m_token;
	};
}