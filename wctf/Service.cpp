#include "Service.h"
#include "LogFile.h"

namespace common {
	Service *Service::instance_;

	Service::Service(const std::string &name,
		bool canStop,
		bool canShutdown,
		bool canPauseContinue
	) :
		name_(name), statusHandle_(NULL)
	{

		// The service runs in its own process.
		status_.dwServiceType = SERVICE_WIN32_OWN_PROCESS;

		// The service is starting.
		status_.dwCurrentState = SERVICE_START_PENDING;

		// The accepted commands of the service.
		status_.dwControlsAccepted = 0;
		if (canStop)
			status_.dwControlsAccepted |= SERVICE_ACCEPT_STOP;
		if (canShutdown)
			status_.dwControlsAccepted |= SERVICE_ACCEPT_SHUTDOWN;
		if (canPauseContinue)
			status_.dwControlsAccepted |= SERVICE_ACCEPT_PAUSE_CONTINUE;

		status_.dwWin32ExitCode = NO_ERROR;
		status_.dwServiceSpecificExitCode = 0;
		status_.dwCheckPoint = 0;
		status_.dwWaitHint = 0;
	}

	Service::~Service()
	{ }

	void Service::run()
	{
		instance_ = this;

		SERVICE_TABLE_ENTRYA serviceTable[] =
		{
			{ const_cast<LPSTR>(name_.c_str()), serviceMain },
		{ NULL, NULL }
		};

		if (!::StartServiceCtrlDispatcherA(serviceTable)) {
			throw std::exception("Failed starting the service");
		}
	}

	void WINAPI Service::serviceMain(
		__in DWORD argc,
		__in_ecount(argc) LPSTR *argv)
	{
		CHECK_NONZERO(instance_ != NULL);



		// Register the handler function for the service
		instance_->statusHandle_ = ::RegisterServiceCtrlHandlerA(
			instance_->name_.c_str(), serviceCtrlHandler);
		if (instance_->statusHandle_ == NULL)
		{
			instance_->setStateStopped(255);
			return;
		}

		// Start the service.
		instance_->setState(SERVICE_START_PENDING);
		instance_->onStart(argc, argv);
	}

	void WINAPI Service::serviceCtrlHandler(DWORD ctrl)
	{
		switch (ctrl)
		{
		case SERVICE_CONTROL_STOP:
			if (instance_->status_.dwControlsAccepted & SERVICE_ACCEPT_STOP) {
				instance_->setState(SERVICE_STOP_PENDING);
				instance_->onStop();
			}
			break;
		case SERVICE_CONTROL_PAUSE:
			if (instance_->status_.dwControlsAccepted & SERVICE_ACCEPT_PAUSE_CONTINUE) {
				instance_->setState(SERVICE_PAUSE_PENDING);
				instance_->onPause();
			}
			break;
		case SERVICE_CONTROL_CONTINUE:
			if (instance_->status_.dwControlsAccepted & SERVICE_ACCEPT_PAUSE_CONTINUE) {
				instance_->setState(SERVICE_CONTINUE_PENDING);
				instance_->onContinue();
			}
			break;
		case SERVICE_CONTROL_SHUTDOWN:
			if (instance_->status_.dwControlsAccepted & SERVICE_ACCEPT_SHUTDOWN) {
				instance_->setState(SERVICE_STOP_PENDING);
				instance_->onShutdown();
			}
			break;
		case SERVICE_CONTROL_INTERROGATE:
			::SetServiceStatus(instance_->statusHandle_, &instance_->status_);
			break;
		default:
			break;
		}
	}

	void Service::setState(DWORD state)
	{
		setStateL(state);
	}

	void Service::setStateL(DWORD state)
	{
		status_.dwCurrentState = state;
		status_.dwCheckPoint = 0;
		status_.dwWaitHint = 0;
		SetServiceStatus(statusHandle_, &status_);
	}

	void Service::setStateStopped(DWORD exitCode)
	{
		status_.dwWin32ExitCode = exitCode;
		setStateL(SERVICE_STOPPED);
	}

	void Service::setStateStoppedSpecific(DWORD exitCode)
	{
		status_.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
		status_.dwServiceSpecificExitCode = exitCode;
		setStateL(SERVICE_STOPPED);
	}

	void Service::bump()
	{
		++status_.dwCheckPoint;
		::SetServiceStatus(statusHandle_, &status_);
	}

	void Service::hintTime(DWORD msec)
	{
		++status_.dwCheckPoint;
		status_.dwWaitHint = msec;
		::SetServiceStatus(statusHandle_, &status_);
		status_.dwWaitHint = 0; // won't apply after the next update
	}

	void Service::onStart(
		__in DWORD argc,
		__in_ecount(argc) LPSTR *argv)
	{
		setState(SERVICE_RUNNING);
	}
	void Service::onStop()
	{
		setStateStopped(NO_ERROR);
	}
	void Service::onPause()
	{
		setState(SERVICE_PAUSED);
	}
	void Service::onContinue()
	{
		setState(SERVICE_RUNNING);
	}
	void Service::onShutdown()
	{
		onStop();
	}

	bool Service::Install() {
		SC_HANDLE scMan = NULL, scSvc = NULL;
		char szSelfPath[MAX_PATH];
		bool result = false;

		CHECK_NONZERO(GetModuleFileNameA(GetModuleHandleA(NULL), szSelfPath, MAX_PATH));

		scMan = ::OpenSCManagerA(
			NULL,
			NULL,
			SC_MANAGER_ALL_ACCESS
		);
		if (!scMan) {
			goto bailout;
		}

		if ((scSvc = ::CreateServiceA(
			scMan,
			name_.c_str(),
			name_.c_str(),
			SERVICE_ALL_ACCESS,
			SERVICE_WIN32_OWN_PROCESS,
			SERVICE_AUTO_START,
			SERVICE_ERROR_IGNORE,
			szSelfPath,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL
		)) == NULL) {
			goto bailout;
		}

		result = true;

	bailout:
		if (scMan) ::CloseServiceHandle(scMan);
		if (scSvc) ::CloseServiceHandle(scSvc);
		return result;
	}

	bool Service::Uninstall() {
		SC_HANDLE scMan = NULL, scSvc = NULL;
		char szSelfPath[MAX_PATH];
		bool result = false;

		CHECK_NONZERO(GetModuleFileNameA(GetModuleHandleA(NULL), szSelfPath, MAX_PATH));

		scMan = ::OpenSCManagerA(
			NULL,
			NULL,
			SC_MANAGER_ALL_ACCESS
		);
		if (!scMan) {
			goto bailout;
		}

		if (!(scSvc = ::OpenServiceA(scMan, name_.c_str(), SERVICE_ALL_ACCESS))) {
			goto bailout;
		}

		if (!::DeleteService(scSvc)) {
			goto bailout;
		}

		result = true;

	bailout:
		if (scMan) ::CloseServiceHandle(scMan);
		if (scSvc) ::CloseServiceHandle(scSvc);
		return result;
	}
}