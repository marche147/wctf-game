#pragma once

#include "Common.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdarg>
#include <ctime>
#include <mutex>

#define LOG CommonLog->log

namespace common {
	const int LogLevelDebug = 0;
	const int LogLevelLog = 1;
	const int LogLevelWarn = 2;
	const int LogLevelError = 3;

	class LogFile {
	public:
		LogFile();
		LogFile(const char* file_name);
		LogFile(const char* file_name, int log_level, bool tempfile = true);
		~LogFile();

		virtual void log(const char* format, ...);
		virtual void debug(const char* format, ...);
		virtual void error(const char* format, ...);
		virtual void warn(const char* format, ...);

	private:
		std::unique_ptr<std::string> m_filePath;
		std::mutex m_logMutex;
		int m_logLevel;
		HANDLE m_fileHandle;

		void vprintf(char* format, va_list args);
		void do_log(const char* tag, const char* fmt, va_list args);
	};

	extern std::unique_ptr<LogFile> CommonLog;
}