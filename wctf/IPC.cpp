#include "IPC.h"

namespace wctf {
	uint32_t IPCBase::read_int() {
		this->check_type(IPC_INT);
		return this->read<uint32_t>();
	}

	void IPCBase::write_int(uint32_t val) {
		this->write<uint8_t>(IPC_INT);
		this->write(val);
		return;
	}

	HANDLE IPCBase::read_handle() {
		this->check_type(IPC_HANDLE);
		return this->read<HANDLE>();
	}

	void IPCBase::write_handle(HANDLE h) {
		HANDLE result = nullptr;

		if (m_process == nullptr) {
			throw std::exception("write_handle can only be called by server-side application");
		}

		if (!::DuplicateHandle(
			::GetCurrentProcess(),
			h,
			m_process,
			&result,
			0,
			FALSE,
			DUPLICATE_SAME_ACCESS
		)) {
			throw std::exception("Failed duplicating handle");
		}

		this->write<uint8_t>(IPC_HANDLE);
		this->write(result);
		return;
	}

	std::string IPCBase::read_string() {
		std::string result = "";
		this->check_type(IPC_STRING);
		auto length = this->read<uintptr_t>();
		for (auto i = 0; i < length; i++) {
			result += this->read<char>();
		}
		return result;
	}

	void IPCBase::write_string(std::string& s) {
		this->write<uint8_t>(IPC_STRING);
		this->write(static_cast<uintptr_t>(s.size()));
		for (auto &c : s) {
			this->write(c);
		}
		return;
	}
	
	std::unique_ptr<common::BinaryStream> IPCBase::read_binary() {
		this->check_type(IPC_BINARY);
		auto length = this->read<uintptr_t>();
		auto result = std::make_unique<common::BinaryStream>(length);
		for (auto i = 0; i < length; i++) {
			result->write(this->read<uint8_t>());
		}
		return std::move(result);
	}

	void IPCBase::write_binary(std::unique_ptr<common::BinaryStream>& val) {
		this->write<uint8_t>(IPC_BINARY);
		this->write(val->length());
		auto ptr = reinterpret_cast<uint8_t*>(val->pointer());
		for (auto i = 0; i < val->length(); i++) {
			this->write(ptr[i]);
		}
		return;
	}

	uint64_t IPCBase::read_int64() {
		this->check_type(IPC_INT64);
		return this->read<uint64_t>();
	}

	void IPCBase::write_int64(uint64_t val) {
		this->write<uint8_t>(IPC_INT64);
		this->write(val);
	}

	void IPCClient::issue_call(uint32_t call) {
		this->write(call);
	}

	void IPCServer::serve_forever(IPCHandler handler, void* context) {
		while (true) {
			auto call_id = this->read<uint32_t>();
			handler(this, call_id, context);
		}
		return;
	}
}