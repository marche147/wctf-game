// wctf.cpp: 定义控制台应用程序的入口点。
//

#include "Common.h"
#include "Sandbox.h"
#include "SocketServer.h"
#include "Service.h"
#include "LogFile.h"

#include "IPC.h"
#include "Game.h"

//#define TEST

#ifndef TEST
#    pragma comment(linker, "/subsystem:windows /ENTRY:mainCRTStartup")
#else
#    pragma comment(linker, "/subsystem:console /ENTRY:mainCRTStartup")
#endif

using namespace common;

namespace wctf {
	HANDLE g_hJob;

	void process_handler(HANDLE hInWrite, HANDLE hOutRead, HANDLE hProcess, HANDLE hJob) {
		auto ipc_server = std::make_unique<IPCServer>(hOutRead, hInWrite, hProcess);

		try {
			ipc_server->serve_forever([](IPCBase* ipc, uint32_t call_id, void* context) {
				if (call_id == 1) {
					auto filename = ipc->read_string();

					if (filename != "banner.txt") {
						ipc->inform_failure();
						return;
					}

					auto handle = ::CreateFileA(filename.c_str(), FILE_READ_DATA, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
					if (handle == INVALID_HANDLE_VALUE) {
						ipc->inform_failure();
						return;
					}
					else {
						ipc->write_handle(handle);
					}
					::CloseHandle(handle);
				}
				else if (call_id == 2) {
					auto keyname = ipc->read_string();
					auto access = ipc->read_int();
					auto options = ipc->read_int();

					std::transform(keyname.begin(), keyname.end(), keyname.begin(), ::tolower);
					if (keyname.find("flag") != -1 || keyname == "") {
						ipc->inform_failure();
						return;
					}

					access &= (KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS);

					HKEY result = nullptr;
					auto fullname = "Software\\WCTF\\" + keyname;
					if (::RegOpenKeyExA(HKEY_LOCAL_MACHINE, fullname.c_str(), options, access, &result) != ERROR_SUCCESS) {
						ipc->inform_failure();
						return;
					}
					ipc->write_handle(result);
					::RegCloseKey(result);
				}
				else if (call_id == 3) {
					auto random = getRandom<uint64_t>();
					ipc->write_int64(random);
				}
				else if (call_id == 4) {
					auto keyname = ipc->read_string();
					auto options = ipc->read_int();
					auto access = ipc->read_int();

					if (keyname == "") {
						ipc->inform_failure();
						return;
					}

					auto fullname = "Software\\WCTF\\LowApps\\" + keyname;
					HKEY result = nullptr;
					if (::RegCreateKeyExA(HKEY_LOCAL_MACHINE, fullname.c_str(), 0, nullptr, options, access, nullptr, &result, nullptr) != ERROR_SUCCESS) {
						ipc->write_int(0);
					}
					else {
						ipc->write_int(1);
					}
					::RegCloseKey(result);
				}
				else if (call_id == 7) {
					auto info = ipc->read_string();
					LOG("From client : %s", info.c_str());
				}
				else if (call_id == 5) {
					auto keyname = ipc->read_string();
					auto valuename = ipc->read_string();
					auto option = ipc->read_int();
					auto type = ipc->read_int();
					auto data = ipc->read_binary();

					if (keyname == "") {
						ipc->inform_failure();
						return;
					}

					auto fullname = "Software\\WCTF\\LowApps\\" + keyname;
					HKEY result = nullptr;
					if (::RegOpenKeyExA(HKEY_LOCAL_MACHINE, fullname.c_str(), option, KEY_WRITE, &result) != ERROR_SUCCESS) {
						ipc->inform_failure();
						return;
					}

#pragma warning(disable:4244)
					DWORD size = data->length();
#pragma warning(default:4244)
					if (::RegSetValueExA(result, valuename.c_str(), 0, type, reinterpret_cast<const BYTE*>(data->pointer()), size) != ERROR_SUCCESS) {
						ipc->write_int(0);
					}
					else {
						ipc->write_int(1);
					}
					::RegCloseKey(result);
				}
				else {
					ipc->inform_failure();
				}
			}, nullptr);
		}
		catch (std::exception& e) {
			LOG("IPC Exception occured (%d) : %s", ::GetProcessId(hProcess), e.what());
		}
		catch (bool) {
			// this is fine, this means the pipe was closed from the other side
		}

		::CloseHandle(hOutRead);
		::CloseHandle(hInWrite);

		if (::WaitForSingleObject(hProcess, INFINITE) == WAIT_OBJECT_0) {
			DWORD exitCode = -1;
			if (::GetExitCodeProcess(hProcess, &exitCode)) {
				LOG("Client %d exited with: %d", ::GetProcessId(hProcess), exitCode);
			}
		}
		::CloseHandle(hProcess);
		::CloseHandle(hJob);
		return;
	}

	void sandbox_launch(HANDLE sock) {
		auto sandbox = std::make_unique<SandboxLauncher>();
		auto lowbox = std::make_unique<LowBoxToken>();
		auto restricted = std::make_unique<FilteredToken>();
		HANDLE hToken = nullptr;

		// TODO : Change this to S4U ?
#if 0
		if (!::LogonUserA("test", ".", "test", LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken)) {	
			throw std::exception("Failed logon user");
		}
#endif

		auto token = LogonS4U(L"test", L".");
		if (!token) {
			throw std::exception("Logon failed");
		}
		if (!::DuplicateTokenEx(token, TOKEN_ALL_ACCESS, nullptr, SecurityDelegation, TokenPrimary, &hToken)) {
			throw std::exception("Cannot duplicate as primary token");
		}
		::CloseHandle(token);

		restricted->with_token(hToken);
		restricted->add_disabled_sid("BA");
		restricted->add_disabled_sid("MU");
		restricted->add_disabled_sid("AU");
		restricted->add_disabled_sid("IU");
		restricted->add_disabled_sid("S-1-2-1");
		restricted->add_disabled_sid("S-1-5-64-10");
		restricted->add_disabled_sid("S-1-5-15");
		restricted->add_disabled_sid("S-1-5-113");
		restricted->add_disabled_sid("S-1-2-0");
#ifdef TEST
		restricted->add_removed_privilege("SeAssignPrimaryTokenPrivilege");
		restricted->add_removed_privilege("SeAuditPrivilege");
		restricted->add_removed_privilege("SeBackupPrivilege");
		restricted->add_removed_privilege("SeCreateGlobalPrivilege");
		restricted->add_removed_privilege("SeCreatePagefilePrivilege");
		restricted->add_removed_privilege("SeCreatePermanentPrivilege");
		restricted->add_removed_privilege("SeCreateSymbolicLinkPrivilege");
		restricted->add_removed_privilege("SeDebugPrivilege");
		restricted->add_removed_privilege("SeDelegateSessionUserImpersonatePrivilege");
		restricted->add_removed_privilege("SeImpersonatePrivilege");
		restricted->add_removed_privilege("SeIncreaseBasePriorityPrivilege");
		restricted->add_removed_privilege("SeIncreaseQuotaPrivilege");
		restricted->add_removed_privilege("SeIncreaseWorkingSetPrivilege");
		restricted->add_removed_privilege("SeLoadDriverPrivilege");
		restricted->add_removed_privilege("SeLockMemoryPrivilege");
		restricted->add_removed_privilege("SeManageVolumePrivilege");
		restricted->add_removed_privilege("SeProfileSingleProcessPrivilege");
		restricted->add_removed_privilege("SeRestorePrivilege");
		restricted->add_removed_privilege("SeSecurityPrivilege");
		restricted->add_removed_privilege("SeShutdownPrivilege");
		restricted->add_removed_privilege("SeSystemEnvironmentPrivilege");
		restricted->add_removed_privilege("SeSystemProfilePrivilege");
		restricted->add_removed_privilege("SeSystemtimePrivilege");
		restricted->add_removed_privilege("SeTakeOwnershipPrivilege");
		restricted->add_removed_privilege("SeTcbPrivilege");
		restricted->add_removed_privilege("SeTimeZonePrivilege");
		restricted->add_removed_privilege("SeUndockPrivilege");
		restricted->disable_all_privileges(false);
		sandbox->restrict_child(false);
#else
		restricted->disable_all_privileges(true);
		sandbox->restrict_child(true);
#endif
		lowbox->with_token(restricted.get());
		lowbox->package_sid("S-1-15-2-1337-1337-1337-13337-13337-13337-13337");

		auto program = GetProcessPath();

		sandbox->restrict_ui_access(true);
		sandbox->executable(program->c_str());
		sandbox->with_token(lowbox.get());

		HANDLE hInRead, hInWrite, hOutRead, hOutWrite;
		if (!::CreatePipe(&hInRead, &hInWrite, nullptr, 0)) {
			throw std::exception("Failed creating pipe");
		}

		if (!::CreatePipe(&hOutRead, &hOutWrite, nullptr, 0)) {
			throw std::exception("Failed creating pipe");
		}

		SandboxLauncher::disable_inherit(hInWrite);
		SandboxLauncher::disable_inherit(hInRead, false);
		SandboxLauncher::disable_inherit(hOutRead);
		SandboxLauncher::disable_inherit(hOutWrite, false);

#pragma warning(disable:4311)
#pragma warning(disable:4302)
		*program += " worker";	// worker process
		*program += " ";
		*program += std::to_string(reinterpret_cast<int>(hInRead));
		*program += " ";
		*program += std::to_string(reinterpret_cast<int>(hOutWrite));
#pragma warning(default:4311)
#pragma warning(default:4302)
		//LOG("Command line: %s", program->c_str());

		sandbox->command_line(program->c_str());
		sandbox->with_stdio(sock, sock, sock);

		auto result = sandbox->launch(
			[](STARTUPINFOEXA& si) {
			//LOG("Launching child...");
		},
			[](PROCESS_INFORMATION& pi, HANDLE hJob) {
			LOG("Child %d launched", ::GetProcessId(pi.hProcess));
			g_hJob = hJob;
		}
		);

		SandboxLauncher::disable_inherit(result.hProcess);
		SandboxLauncher::disable_inherit(g_hJob);

		std::thread t1(process_handler, hInWrite, hOutRead, result.hProcess, g_hJob); t1.detach();
		::ResumeThread(result.hThread);
		
		::CloseHandle(result.hThread);
		::CloseHandle(hInRead);
		::CloseHandle(hOutWrite);
		return;
	}

	class VMService : public Service {
	public:
		VMService(const char* name) : Service(std::string(name), true, true, false) {
			m_server = nullptr;
			m_daemon = nullptr;
		}

		virtual void onStart(
			__in DWORD argc,
			__in_ecount(argc) LPSTR *argv) {
			LOG("Daemon starting");
			try {
				registry_probe();

				m_working = true;
				m_daemon = std::move(std::make_unique<std::thread>(&VMService::workerThread, this));
			}
			catch (std::exception& e) {
				LOG(e.what());
				setStateStopped(1);
				return;
			}
			
			setState(SERVICE_RUNNING);
		}

		virtual void onStop() {
			LOG("Daemon stopping");
			try {
				m_working = false;
				::TerminateProcess(m_server, 0);
				m_daemon->join();
			}
			catch (std::exception& e) {
				LOG(e.what());
			}
			LOG("Daemon stopped");

			setStateStopped(0);
		}

		virtual void onShutdown() {
			onStop();
		}

	private:
		void workerThread(void) {
			STARTUPINFOA si;
			PROCESS_INFORMATION pi;

			while (m_working) {
				auto program = GetProcessPath();
				auto commandline = GetProcessPath();

				*commandline += " server";
				::RtlZeroMemory(&si, sizeof(si));
				si.cb = sizeof(si);
				
				if (::CreateProcessA(program->c_str(), const_cast<LPSTR>(commandline->c_str()), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi)) {
					LOG("Server launched: %d", pi.dwProcessId);
					::CloseHandle(pi.hThread);

					m_server = pi.hProcess;
					if (::WaitForSingleObject(pi.hProcess, INFINITE) == WAIT_OBJECT_0) {
						DWORD exitCode;
						if (::GetExitCodeProcess(pi.hProcess, &exitCode)) {
							LOG("Server exited with: %d", exitCode);
						}
					}
					::CloseHandle(pi.hProcess);
					::Sleep(1000);
				}
				else {
					LOG("Failed launch server: %d, will try to relaunch in 5 seconds.", ::GetLastError());
					::Sleep(5000);
				}
			}
		}

		void registry_probe() {
			HKEY result = nullptr;
			HKEY lowkey = nullptr;
			DWORD type = 0;
			DWORD cbData;
			BYTE bData[0x100];

			if (::RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\WCTF", 0, KEY_ALL_ACCESS, &result) != ERROR_SUCCESS) {
				throw std::exception("Missing wctf registry key");
			}
			::RegCloseKey(result);

			if (::RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\WCTF\\Config", 0, KEY_ALL_ACCESS, &result) != ERROR_SUCCESS) {
				throw std::exception("Missing wctf registry key");
			}
			::RegCloseKey(result);

			if (::RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\WCTF\\LowApps", 0, KEY_ALL_ACCESS, &lowkey) != ERROR_SUCCESS) {
				throw std::exception("Missing lowapp registry key");
			}
			::RegCloseKey(lowkey);

			if (::RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\WCTF\\Flag", 0, KEY_ALL_ACCESS, &lowkey) != ERROR_SUCCESS) {
				throw std::exception("Missing flag registry key");
			}
			cbData = sizeof(bData);
			if (::RegQueryValueExA(lowkey, "flag", nullptr, &type, bData, &cbData) != ERROR_SUCCESS) {
				throw std::exception("Missing flag value");
			}
			if (type != REG_SZ) {
				throw std::exception("Invalid flag type");
			}
			::RegCloseKey(lowkey);
			
			return;
		}

		HANDLE m_server;
		bool m_working;
		std::unique_ptr<std::thread> m_daemon;
	};

	int my_entry(std::vector<std::string>& args) {
		auto svc = std::make_shared<VMService>("wctf");

		if (args.size() == 2 && args[1] == "install") {
			if (svc->Install()) {
				std::cout << "Service successfully installed" << std::endl;
			}
			else {
				std::cout << "Failed installing service" << std::endl;
			}
		}
		else if (args.size() == 2 && args[1] == "uninstall") {
			if (svc->Uninstall()) {
				std::cout << "Service successfully uninstalled" << std::endl;
			}
			else {
				std::cout << "Failed uninstalling service" << std::endl;
			}
		}
		else if (args.size() >= 2 && args[1] == "worker") {		// worker
			if (!SandboxLauncher::enable_mitigation()) {
				std::cerr << "Failed enabling mitigations" << std::endl;
				::_exit(255);
			}

			if (!SandboxLauncher::lockdown()) {
				std::cerr << "Failed lockdown" << std::endl;
				::_exit(254);
			}
			
#pragma warning(disable:4312)
			HANDLE hInRead = reinterpret_cast<HANDLE>(std::stoi(args[2]));
			HANDLE hOutWrite = reinterpret_cast<HANDLE>(std::stoi(args[3]));
#pragma warning(default:4312)

			auto ipc_client = std::make_unique<IPCClient>(hInRead, hOutWrite);

			//std::cout << "Child here: " << ::GetCurrentProcessId() << std::endl;
			//std::cin.get();

			auto game = std::make_unique<Game>(ipc_client);

			try {
				game->play();
			}
			catch (std::exception& e) {
				std::cerr << "Exception: " << e.what() << std::endl;
			}
#if 0
			HKEY handle;
			auto result = ::RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\WCTF\\LowApps", 0, KEY_QUERY_VALUE, &handle);
			if (result != ERROR_SUCCESS) {
				std::cout << "Error : " << result << std::endl;
			}
			else {
				::RegCloseKey(handle);
			}
#endif

#if 0
			try {
				ipc_client->issue_call(4);
				ipc_client->write_string("link2");
				ipc_client->write_int(REG_OPTION_CREATE_LINK);
				ipc_client->write_int(KEY_ALL_ACCESS);
				auto result = ipc_client->read_int();

				if (result == 1) {
					ipc_client->issue_call(5);
					ipc_client->write_string("link2");
					ipc_client->write_string("SymbolicLinkValue");
					ipc_client->write_int(REG_OPTION_OPEN_LINK);
					ipc_client->write_int(REG_LINK);
					wchar_t symlink[] = L"\\REGISTRY\\MACHINE\\SOFTWARE\\WCTF\\Flag";
					ipc_client->write_binary(symlink, sizeof(symlink) - 2);
					auto ret = ipc_client->read_int();
					if (ret == 1) {
						ipc_client->issue_call(2);
						ipc_client->write_string("LowApps\\link2");
						ipc_client->write_int(KEY_ALL_ACCESS);
						ipc_client->write_int(0);
						auto handle = reinterpret_cast<HKEY>(ipc_client->read_handle());
						DWORD type, size;
						BYTE data[100];
						size = sizeof(data);
						if (::RegQueryValueExA(handle, "flag", nullptr, &type, reinterpret_cast<LPBYTE>(&data), &size) != ERROR_SUCCESS) {
							std::cerr << "Cannot query value" << std::endl;
						}
						else {
							std::cout << "Value: " << data << std::endl;
						}
					}
				}
			}
			catch (std::exception&) {
				std::cerr << "IPC Exception" << std::endl;
			}
#endif

			::CloseHandle(hInRead);
			::CloseHandle(hOutWrite);
		}
		else if (args.size() == 2 && args[1] == "server") {
			CommonLog = std::move(std::make_unique<LogFile>("server.log", LogLevelDebug));
			LOG("Server started");

			try {
				// Initialization
				WSADATA data;
				if (::WSAStartup(MAKEWORD(2, 2), &data)) {
					throw std::exception("WSAStartup failed");
				}

				if (!EnablePrivilege("SeTcbPrivilege")) {
					throw std::exception("Failed to acquire privilege");
				}

				if (!::SetCurrentDirectoryA("C:\\ctf\\")) {
					throw std::exception("Failed to setcwd");
				}

				auto server = std::move(std::make_unique<SocketServer>("0.0.0.0", 13337));
				auto daemon = std::move(std::make_unique<std::thread>([&server]() {
					server->serve_forever([](SOCKET s, struct sockaddr_in* addr) {
						LOG("Incoming connection from %s", ::inet_ntoa(addr->sin_addr));
						try {
							sandbox_launch(reinterpret_cast<HANDLE>(s));
						}
						catch (std::exception& e) {
							LOG("Exception when launching for client: %s", e.what());
						}
						::closesocket(s);
					});
				}));
				daemon->join();

				::WSACleanup();
			}
			catch (std::exception& e) {
				LOG(e.what());
				return 1;
			}
		}
		else { // daemon
			CommonLog = std::move(std::make_unique<LogFile>("daemon.log", LogLevelDebug));
			svc->run();
		}
		return 0;
	}
}

int main(int argc, char* argv[]) {
	std::vector<std::string> args;
	for (auto i = 0; i < argc; i++) {
		args.push_back(std::string(argv[i]));
	}
    return wctf::my_entry(args);
}

