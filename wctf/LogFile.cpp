#include "LogFile.h"

#define BUFFER_SIZE 512

namespace common {
	std::unique_ptr<LogFile> CommonLog = nullptr;

	LogFile::LogFile(const char* file_name, int log_level, bool tempfile) {
		m_logLevel = log_level;
		//if (::PathIsRelativeA(file_name)) {	// Shlwapi uses gdi32 & user32....
		if(tempfile) {
			char temp_path[MAX_PATH];

			::ZeroMemory(temp_path, sizeof(temp_path));
			CHECK_NONZERO(::GetTempPathA(sizeof(temp_path), temp_path));
			CHECK_HRESULT(::StringCbCatA(temp_path, sizeof(temp_path), file_name));
			m_filePath = std::make_unique<std::string>(temp_path);
		}
		else {
			m_filePath = std::make_unique<std::string>(file_name);
		}

		m_fileHandle = ::CreateFileA(
			m_filePath->c_str(),
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ,
			NULL,
			OPEN_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);
		CHECK_NONZERO(m_fileHandle != INVALID_HANDLE_VALUE);
		CHECK_NONZERO(::SetFilePointer(m_fileHandle, 0, NULL, FILE_END) != INVALID_SET_FILE_POINTER)
	}

	LogFile::LogFile(const char* filePath) : LogFile(filePath, LogLevelWarn) { }
	LogFile::LogFile() : LogFile("program.log") { }

	LogFile::~LogFile() {
		::CloseHandle(m_fileHandle);
	}

	void LogFile::vprintf(char* format, va_list args) {
		char temp_buf[BUFFER_SIZE];
		size_t write_len;
		DWORD retlen;

#pragma warning(disable:4267)
		m_logMutex.lock();
		CHECK_HRESULT(::StringCbVPrintfA(temp_buf, BUFFER_SIZE, format, args));
		CHECK_HRESULT(::StringCbLengthA(temp_buf, BUFFER_SIZE, &write_len));
		CHECK_NONZERO(::WriteFile(m_fileHandle, temp_buf, write_len, &retlen, NULL));
		m_logMutex.unlock();
#pragma warning(default:4267)
		return;
	}

	void LogFile::do_log(const char* tag, const char *format, va_list args) {
		char temp_buf[BUFFER_SIZE];
		char format_buf[BUFFER_SIZE];
		struct tm t;
		auto current = ::time(nullptr);
		CHECK_ZERO(::localtime_s(&t, &current));
		::strftime(temp_buf, BUFFER_SIZE, "%F %T [%%s]: %%s\n", &t);
		CHECK_HRESULT(::StringCbPrintfA(format_buf, BUFFER_SIZE, temp_buf, tag, format));
		this->vprintf(format_buf, args);
		return;
	}

	void LogFile::debug(const char* format, ...) {
		va_list args;

		if (m_logLevel > LogLevelDebug) return;
		va_start(args, format);
		this->do_log("DEBUG", format, args);
		va_end(args);
	}

	void LogFile::log(const char* format, ...) {
		va_list args;

		if (m_logLevel > LogLevelLog) return;
		va_start(args, format);
		this->do_log("INFO", format, args);
		va_end(args);
	}

	void LogFile::warn(const char* format, ...) {
		va_list args;

		if (m_logLevel > LogLevelWarn) return;
		va_start(args, format);
		this->do_log("WARN", format, args);
		va_end(args);
	}

	void LogFile::error(const char* format, ...) {
		va_list args;

		if (m_logLevel > LogLevelError) return;
		va_start(args, format);
		this->do_log("ERROR", format, args);
		va_end(args);
	}
}