#pragma once

#include "Common.h"

namespace common {
	class BinaryStream {
	public:
		BinaryStream(uintptr_t length);
		BinaryStream(void* ptr, uintptr_t length);
		~BinaryStream();
		void skip(uintptr_t offset);
		void rewind(uintptr_t offset);

		template<typename T> T read() {
			if (sizeof(T) > remaining()) {
				throw std::out_of_range("Not enough size for read");
			}

			T* ptr = reinterpret_cast<T*>((uintptr_t)m_pointer + m_offset);
			m_offset += sizeof(T);
			return (*ptr);
		}

		template<typename T> void write(T val) {
			if (sizeof(T) > remaining()) {
				throw std::out_of_range("Not enough size for write");
			}

			T* ptr = reinterpret_cast<T*>((uintptr_t)m_pointer + m_offset);
			m_offset += sizeof(T);
			(*ptr) = val;
		}

		void* pointer() {
			return m_pointer;
		}

		uintptr_t length() {
			return m_capacity;
		}

	private:
		uintptr_t remaining();

		void* m_pointer;
		uintptr_t m_capacity;
		uintptr_t m_offset;
		bool m_alloc;
	};
}