#include "BinaryStream.h"

namespace common {
	BinaryStream::BinaryStream(void* pointer, uintptr_t length) {
		if (!pointer) {
			throw std::exception("Invalid argument");
		}
		m_pointer = pointer;
		m_capacity = length;
		m_offset = 0;
		m_alloc = false;
	}

	BinaryStream::BinaryStream(uintptr_t length) : BinaryStream(
		::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, length), 
		length
	){
		m_alloc = true;
	}

	BinaryStream::~BinaryStream() {
		if (m_alloc) {
			::HeapFree(::GetProcessHeap(), 0, m_pointer);
		}
	}

	inline void BinaryStream::skip(uintptr_t offset) {
		if (offset + m_offset > m_capacity) {
			m_offset = m_capacity;
		}
		else {
			m_offset += offset;
		}
	}

	inline void BinaryStream::rewind(uintptr_t offset) {
		if (m_offset < offset) {
			m_offset = 0;
		}
		else {
			m_offset -= offset;
		}
	}

	uintptr_t BinaryStream::remaining() {
		return m_capacity - m_offset;
	}

}