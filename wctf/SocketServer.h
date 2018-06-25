#pragma once

#include "Common.h"
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")

#define DEFAULT_BACKLOG 5
#define SECURE 1

namespace common {
	using NewConnectionCallback = void (SOCKET, struct sockaddr_in*);

	class SocketServer {
	public:
		SocketServer(const char* address, uint16_t port);
		~SocketServer();

		void serve_forever(NewConnectionCallback callback);
		void kill();

	private:

		bool m_serving;
		WSAEVENT m_sockEvent, m_exitEvent;
		SOCKET m_socket;
	};
}