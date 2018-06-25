#include "Game.h"

using namespace common;

namespace wctf {
	uint64_t Game::random() {
		m_client->issue_call(3);
		return m_client->read_int64();
	}

	void Game::notify_server(const char* s) {
		m_client->issue_call(7);
		m_client->write_string(s);
		return;
	}

	void Game::notify_server(std::string& s) {
		m_client->issue_call(7);
		m_client->write_string(s);
		return;
	}

	HANDLE Game::open_file(const char* s) {
		m_client->issue_call(1);
		m_client->write_string(s);
		return m_client->read_handle();
	}

	HKEY Game::open_key(const char* s, uint32_t access, uint32_t option) {
		m_client->issue_call(2);
		m_client->write_string(s);
		m_client->write_int(access);
		m_client->write_int(option);
		return reinterpret_cast<HKEY>(m_client->read_handle());
	}

	void Game::print_banner() {
		char buffer[0x100];
		try {
			auto handle = this->open_file("banner.txt");
			auto outhandle = ::GetStdHandle(STD_OUTPUT_HANDLE);
			while (true) {
				DWORD retlen;
				if (!::ReadFile(handle, buffer, sizeof(buffer), &retlen, nullptr)) {
					break;
				}
				if (retlen == 0) break;
				::WriteFile(outhandle, buffer, retlen, &retlen, nullptr);
			}
			::CloseHandle(handle);
		}
		catch (std::exception&) {
			std::cerr << "Cannot open banner file." << std::endl;
		}
		return;
	}

	void Game::read_config() {
		auto key = this->open_key("Config");

		if (!QueryRegValueDword(key, "MaximumGuessTrials", &m_threshold)) {
			throw std::exception("Cannot read registry value");
		}

		::RegCloseKey(key);
	}

	void Game::menu() {
		std::cout << "Menu: " << std::endl;
		std::cout << "1. Start a new round" << std::endl;
		std::cout << "2. Show highscores" << std::endl;
 		std::cout << "0. Exit" << std::endl;
		std::cout << "Choice: ";
		return;
	}

	void Game::store_result(uint8_t* scores, int rounds) {
		auto result = std::make_unique<std::vector<uint8_t>>();
		std::for_each(scores, scores + rounds, [&result](uint8_t& val) {
			result->push_back(val);
		});
		m_scores.push_back(std::move(result));
	}

	void Game::new_round() {
		uint8_t previous[0x40];
		int round = 0;
		uint8_t score;
		
		auto seed = this->random();
		std::srand(static_cast<uint32_t>(seed));
		while (round < 0x40) {
			std::cout << "Round #" << round << std::endl;
			score = 0xff;
			auto number = static_cast<uint8_t>(std::rand() & 0xff);
			auto trial_left = m_threshold;

			while (true) {
				std::cout << "1. Ask" << std::endl;
				std::cout << "2. Guess" << std::endl;
				std::cout << "3. Check previous score" << std::endl;
				std::cout << "4. Load previous scores" << std::endl;
				std::cout << "0. Go back" << std::endl;
				std::cout << "Choice: ";

				int choice; std::cin >> choice;
				if (choice == 0) {
					goto game_over;
				}
				else if (choice == 1) {
					if (trial_left != 0) {
						std::cout << "Ask me, I'll show you the way: ";
						int question; std::cin >> question;
						if (static_cast<uint8_t>(question) == number) {
							std::cout << "That's it!" << std::endl;
						}
						else if (static_cast<uint8_t>(question) > number) {
							std::cout << "Too big, try something smaller." << std::endl;
						}
						else {
							std::cout << "Too small." << std::endl;
						}
						trial_left--;
					}
					else {
						std::cout << "No more questions, try harder!" << std::endl;
					}
				}
				else if (choice == 2) {
					std::cout << "Show me your answer: ";
					int answer; std::cin >> answer;
					if (answer == static_cast<int>(number)) {
						std::cout << "Correct!" << std::endl;
						break;
					}
					else {
						std::cout << "Wrong!" << std::endl;
						score--;
					}
				}
				else if (choice == 3) {
					std::cout << "Round number: ";
					int index; std::cin >> index;
					std::cout << "Round #" << index << ": " << static_cast<int>(previous[index]) << std::endl;	// leak
				}
				else if (choice == 4) {
					std::cout << "Round number: ";
					int index; std::cin >> index;
					if (static_cast<size_t>(index) >= m_scores.size()) {
						std::cout << "Invalid index." << std::endl;
					}
					std::for_each(m_scores[index]->begin(), m_scores[index]->end(), [&previous, &round](uint8_t& val) {
						previous[round++] = val;
					});
					std::cout << "Done!" << std::endl;
				}
			}
			previous[round++] = score;
		}

	game_over:
		std::cout << "Game over! Thanks for playing!" << std::endl;
		this->store_result(previous, round);
		return;
	}

	void Game::play() {
		int choice;

		this->read_config();
		this->print_banner();
		while (true) {
			this->menu();
			std::cin >> choice;
			if (choice == 0) {
				break;
			}
			else if (choice == 1) {
				this->new_round();
			}
			else if (choice == 2) {
				uint32_t high_score = 0;
				std::for_each(m_scores.begin(), m_scores.end(), [&high_score](std::unique_ptr<std::vector<uint8_t>>& v) {
					auto result = std::accumulate(v->begin(), v->end(), static_cast<uint32_t>(0));
					if (result > high_score) {
						high_score = result;
					}
				});
				std::cout << "Highest: " << high_score << std::endl;
			}
			else {
				std::cout << "Invalid choice" << std::endl;
			}
		}

		return;
	}
}