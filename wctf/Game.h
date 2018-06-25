#pragma once

#include "Common.h"

#include "IPC.h"

namespace wctf {
	class Game {
	public:
		Game(std::unique_ptr<IPCClient>& client) {
			m_client = std::move(client);
			m_threshold = 0;
		}

		~Game() {

		}

		void play();

	private:

		HANDLE open_file(const char* s);
		HKEY open_key(const char* s, uint32_t access = KEY_QUERY_VALUE, uint32_t option = 0);
		uint64_t random();
		void notify_server(std::string& s);
		void notify_server(const char* s);

		void read_config();
		void print_banner();
		void menu();

		void new_round();

		void store_result(uint8_t* scores, int rounds);

		uint32_t m_threshold;
		std::unique_ptr<IPCClient> m_client;
		std::vector<std::unique_ptr<std::vector<uint8_t>>> m_scores;
	};
}