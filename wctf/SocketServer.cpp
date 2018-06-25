#include "SocketServer.h"

namespace common {
	SocketServer::SocketServer(const char* address, uint16_t port) {
		m_socket = ::WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, 0);
		if (m_socket == INVALID_SOCKET) {
			throw std::exception("WSASocket failed");
		}

		const int option = 1;
		if (::setsockopt(
			m_socket,
			SOL_SOCKET,
			SO_REUSEADDR,
			reinterpret_cast<const char*>(&option),
			sizeof(option)
		) != 0) {
			throw std::exception("setsockopt failed");
		}

		struct sockaddr_in addr;
		::RtlZeroMemory(&addr, sizeof(addr));
		addr.sin_port = ::htons(port);
		addr.sin_addr.S_un.S_addr = ::inet_addr(address);
		addr.sin_family = AF_INET;

		if (::bind(m_socket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr))) {
			throw std::exception("bind failed");
		}

		if (::listen(m_socket, DEFAULT_BACKLOG) != 0) {
			throw std::exception("listen failed");
		}

#ifdef SECURE
		if (::SetHandleInformation(
			reinterpret_cast<HANDLE>(m_socket),
			HANDLE_FLAG_INHERIT,
			0
		) != TRUE) {
			throw std::exception("SetHandleInformation failed");
		}
#endif

		m_serving = false;
		m_sockEvent = ::CreateEventA(nullptr, FALSE, FALSE, nullptr);
		m_exitEvent = ::WSACreateEvent();

		if (::WSAEventSelect(m_socket, m_sockEvent, FD_ACCEPT) != 0) {
			throw std::exception("WSAEventSelect failed");
		}
	}

	SocketServer::~SocketServer() {
		::WSACloseEvent(m_sockEvent);
		::WSACloseEvent(m_exitEvent);
		::closesocket(m_socket);
	}

	void SocketServer::kill() {
		if (m_serving) {
			::WSASetEvent(m_exitEvent);
		}
	}

	void SocketServer::serve_forever(NewConnectionCallback callback) {
		WSAEVENT events[] = { m_sockEvent, m_exitEvent };
		struct sockaddr_in addr;
		int length = sizeof(addr);

		m_serving = true;
		while (true) {
			auto retcode = ::WSAWaitForMultipleEvents(2, events, FALSE, INFINITE, FALSE);
			if (retcode == WSA_WAIT_EVENT_0) {
				auto client = ::accept(
					m_socket,
					reinterpret_cast<sockaddr*>(&addr),
					&length
				);
				callback(client, &addr);
			}
			else if (retcode == WSA_WAIT_EVENT_0 + 1) {
				break;
			}
		}
	}
}