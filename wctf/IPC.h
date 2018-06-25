#pragma once

#include "Common.h"
#include "BinaryStream.h"

namespace wctf {

#define IPC_INT 1
#define IPC_HANDLE 2
#define IPC_STRING 3
#define IPC_INT64 4
#define IPC_BINARY 5
#define IPC_FAIL 0xff

	class IPCBase {
	public:
		IPCBase(HANDLE hRead, HANDLE hWrite, HANDLE hProcess = nullptr) {
			m_read = hRead;
			m_write = hWrite;
			m_process = hProcess;
		}

		~IPCBase() {

		}

		virtual uint32_t read_int();
		virtual HANDLE read_handle();
		virtual std::string read_string();
		virtual uint64_t read_int64();
		virtual std::unique_ptr<common::BinaryStream> read_binary();

		virtual void write_int(uint32_t val);
		virtual void write_handle(HANDLE h);
		virtual void write_string(std::string& s);
		inline void write_string(const char* s) {
			std::string v(s);
			this->write_string(v);
		}
		virtual void write_int64(uint64_t val);
		virtual void write_binary(std::unique_ptr<common::BinaryStream>& stream);
		inline void write_binary(void* buffer, uintptr_t size) {
			auto stream = std::make_unique<common::BinaryStream>(buffer, size);
			this->write_binary(stream);
		}

		inline void inform_failure() {
			this->write<uint8_t>(IPC_FAIL);
		}

		template<typename T> T read() {
			T ret;
			DWORD bytes_read;
			if (::ReadFile(m_read, reinterpret_cast<LPVOID>(&ret), sizeof(T), &bytes_read, nullptr)) {
				if (bytes_read == sizeof(T)) {
					return ret;
				}
			}

			if (::GetLastError() == ERROR_BROKEN_PIPE) {
				throw true;
			}
			throw std::exception("Failed read IPC element");
		}

		template<typename T> void write(T val) {
			DWORD bytes_written;
			if (::WriteFile(m_write, reinterpret_cast<LPVOID>(&val), sizeof(T), &bytes_written, nullptr)) {
				if (bytes_written == sizeof(T)) {
					return;
				}
			}
			throw std::exception("Failed write IPC element");
		}

	private:

		inline void check_type(uint8_t type) {
			auto typ = this->read<uint8_t>();
			if (type != typ) {
				throw std::exception("Incorrect element type");
			}
			return;
		}

		HANDLE m_read, m_write, m_process;
	};

	class IPCClient : public IPCBase {
	public:
		IPCClient(HANDLE hRead, HANDLE hWrite) : IPCBase(hRead, hWrite, nullptr){

		}

		void issue_call(uint32_t call);
	};

	using IPCHandler = void(IPCBase*, uint32_t, void*);

	class IPCServer : public IPCBase {
	public:
		IPCServer(HANDLE hRead, HANDLE hWrite, HANDLE hProcess) : IPCBase(hRead, hWrite, hProcess) {

		}

		void serve_forever(IPCHandler handler, void* context = nullptr);
	};
}