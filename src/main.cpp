#include "global.hpp"
#include <cstdio>
#include <kita/kita.hpp>
#include <thread>
#include <Windows.h>
#include <winternl.h>
#include <filesystem>
#include <future>
#include "utils.hpp"
#include "echo.hpp"

static auto on_pre_render(kita::events::on_pre_render * e) -> void
{
	std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

static auto on_render(kita::events::on_render * e) -> void
{
	ImGui::Text("bad_echo | FPS: %f", ImGui::GetIO().Framerate);

	// ObRegisterCallback
	ImGui::Separator();
	static const char * obrc_status = "...";
	static bool obrc_working = false;
	static int obrc_pids[4] = {};
	ImGui::Text("ObRegisterCallback:");
	ImGui::Text("PID Protect:");
	ImGui::SameLine();
	ImGui::InputInt("##pidprot", &obrc_pids[0]);
	ImGui::Text("Protection whitelist:");
	for (int i = 1; i < 4; ++i)
	{
		ImGui::Text("PID %d:", i);
		ImGui::SameLine();
		ImGui::PushID(i);
		ImGui::InputInt("", &obrc_pids[i]);
		ImGui::PopID();
	}

	if (ImGui::Button("Apply") && !obrc_working)
	{
		obrc_status = "Requesting...";
		obrc_working = true;
		static std::future<void> _; _ = std::async(std::launch::async, [&] {
			echo::req_obrcb_protect req = {};
			for (int _ri = 0; _ri < 4; ++_ri) ((int *)&req)[_ri] = obrc_pids[_ri];
			obrc_status = echo::ioctl_request(req) == echo::INVALID_REQUEST ? "Failed" : "Success";
			obrc_working = false;
		});
	}
	ImGui::SameLine();
	ImGui::Text("%s", obrc_status);

	// Protect / Unprotect process
	ImGui::Separator();
	static int pup_pid = 0;
	static bool pup_working = false;
	static const char * pup_status = "...";
	ImGui::Text("Protected Process");
	ImGui::Text("PID:");
	ImGui::SameLine();
	ImGui::InputInt("##pup", &pup_pid);

	if (ImGui::Button("Protect") && !pup_working)
	{
		pup_working = true;
		pup_status = "Requesting...";
		static std::future<void> _; _ = std::async(std::launch::async, [&] {
			echo::req_proc_protect req = { .pid = (DWORD)pup_pid, .prot_flag = 1 };
			pup_status = echo::ioctl_request(req) == echo::INVALID_REQUEST ? "Failed" : "Success";
			pup_working = false;
		});
	}
	ImGui::SameLine();
	if (ImGui::Button("Unprotect") && !pup_working)
	{
		pup_working = true;
		pup_status = "Requesting...";
		static std::future<void> _; _ = std::async(std::launch::async, [&] {
			echo::req_proc_unprotect req = { .pid = (DWORD)pup_pid };
			pup_status = echo::ioctl_request(req) == echo::INVALID_REQUEST ? "Failed" : "Success";
			pup_working = false;
		});
	}
	ImGui::SameLine();
	ImGui::Text("%s", pup_status);
}

static auto get_service_handle(SC_HANDLE sc_manager, const char * driver_path) -> SC_HANDLE
{
	SC_HANDLE out = CreateServiceA(sc_manager, echo::SRV_NAME, echo::SRV_NAME, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, driver_path, nullptr, nullptr, nullptr, nullptr, nullptr);
	if (!out && GetLastError() == ERROR_SERVICE_EXISTS)
		out = OpenServiceA(sc_manager, echo::SRV_NAME, SERVICE_ALL_ACCESS);
	return out;
}

auto main() -> int
{
	if (DWORD con_pid = 0; !GetWindowThreadProcessId(GetConsoleWindow(), &con_pid) || con_pid == GetCurrentProcessId())
	{
		printf("\n[?] Run this in a console to read logs. Press enter to continue and ignore.");
		getchar();
	}

	if (!std::filesystem::exists(echo::SYS_FILE_NAME))
	{
		printf("\n[!] Driver file (%s) not found.", echo::SYS_FILE_NAME);
		return 1;
	}

	printf("\n[+] Creating Service Manager...");
	SC_HANDLE sch_manager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!sch_manager)
	{
		printf("\n[!] OpenSCManager failed. GLE: %lu", GetLastError());
		return 1;
	}
	UTILS_DEFER {
		printf("\n[+] Closing service manager...");
		CloseServiceHandle(sch_manager);
	};
	printf(" 0x%p", sch_manager);

	char driver_full_path[256] = {};
	if (GetFullPathNameA(echo::SYS_FILE_NAME, sizeof(driver_full_path), driver_full_path, nullptr) == 0)
	{
		printf("\n[!] Driver full path failed.");
		return 1;
	}
	printf("\n[+] Driver path: %s", driver_full_path);

	printf("\n[+] Creating service handle for driver...");
	echo::service_handle = get_service_handle(sch_manager, driver_full_path);
	if (!echo::service_handle)
	{
		printf("\n[!] Failed to create service handle. GLE: %lu", GetLastError());
		return 1;
	}
	UTILS_DEFER {
		printf("\n[+] Deleting service... %s | GLE: %lu", DeleteService(echo::service_handle) ? "OK!" : "Failed!", GetLastError());
		printf("\n[+] Closing driver handle...");
		CloseServiceHandle(echo::service_handle);
	};
	printf(" 0x%p", echo::service_handle);

	printf("\n[+] Starting service...");
	if (SERVICE_STATUS ss {}; !StartServiceA(echo::service_handle, 0, nullptr))
	{
		auto e_code = GetLastError();
		if (e_code != ERROR_SERVICE_ALREADY_RUNNING)
		{
			#if 0
			printf("\n[?] Service is already running.\n[+] Telling service to stop...");
			if (SERVICE_STATUS ss {}; !ControlService(echo::service_handle, SERVICE_CONTROL_STOP, &ss))
			{
				printf("\n[!] Failed to stop service. GLE: %lu", GetLastError());
				return 1;
			}
			printf(" OK!\n[?] Service stopped. Try again.");
			#endif

			printf("\n[!] Failed to start service. GLE: %lu", e_code);
			return 1;
		}
		printf("\n[?] Service is already running.");
	}
	printf(" OK!");
	UTILS_DEFER {
		SERVICE_STATUS ss {};
		printf("\n[+] Stopping driver... %s! | GLE: %lu", ControlService(echo::service_handle, SERVICE_CONTROL_STOP, &ss) ? "OK" : "Failed", GetLastError());
	};

	printf("\n[+] Loading ntdll...");
	HMODULE mod_ntdll = GetModuleHandleA("ntdll.dll");
	if (!mod_ntdll)
	{
		printf("\n[!] Failed to load ntdll! That's not supposed to happen.");
		return 1;
	}
	printf(" 0x%p", mod_ntdll);

	printf("\n[+] Importing ntdll.RtlInitUnicodeString...");
	decltype(RtlInitUnicodeString) * _RtlInitUnicodeString = (decltype(_RtlInitUnicodeString))GetProcAddress(mod_ntdll, "RtlInitUnicodeString"); 
	if (!_RtlInitUnicodeString)
	{
		printf("\n[!] Failed to import ntdll.RtlInitUnicodeString");
		return 1;
	}
	printf(" 0x%p", _RtlInitUnicodeString);

	UNICODE_STRING dev_name {};
	_RtlInitUnicodeString(&dev_name, L"\\??\\EchoDrv");

	OBJECT_ATTRIBUTES oa {};
	InitializeObjectAttributes(&oa, &dev_name, OBJ_CASE_INSENSITIVE, NULL, NULL);
	IO_STATUS_BLOCK iosb {};

	printf("\n[+] Importing ntdll.NtCreateFile...");
	decltype(NtCreateFile) * _NtCreateFile = (decltype(_NtCreateFile))GetProcAddress(mod_ntdll, "NtCreateFile");
	if (!_NtCreateFile)
	{
		printf("\n[!] Failed to import kernelbase.NtCreateFile");
		return 1;
	}
	printf(" 0x%p", _NtCreateFile);

	printf("\n[+] Creating device handle...");
	if (!NT_SUCCESS(_NtCreateFile(&echo::device_handle, FILE_READ_ATTRIBUTES | GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &oa, &iosb, NULL, NULL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, NULL)) || !echo::device_handle)
	{
		printf("\n[!] Failed to create device handle. GLE: %lu", GetLastError());
		return 1;
	}
	printf(" 0x%p", echo::device_handle);
	UTILS_DEFER {
		printf("\n[+] Closing device handle... %s! | GLE: %lu", CloseHandle(echo::device_handle) ? "OK" : "Failed", GetLastError());
	};

	printf("\n[+] Importing ntdll.NtDeviceIoControlFile...");
	_NtDeviceIoControlFile = (decltype(_NtDeviceIoControlFile))GetProcAddress(mod_ntdll, "NtDeviceIoControlFile");
	if (!_NtDeviceIoControlFile)
	{
		printf("\n[!] Failed to import ntdll.NtDeviceIoControlFile");
		return 1;
	}
	printf(" 0x%p", _NtDeviceIoControlFile);

	printf("\n[+] Sending false verification for initializing PID field...");
	echo::req_verify_signature req_verify = {
		.pb_sig = nullptr,
		.cb_sig = 0,
		.is_successful = true, // set back to false for fail which is what we expect
	};
	if (echo::ioctl_request(req_verify) == echo::INVALID_REQUEST)
	{
		printf("\n[!] Verification request failed. GLE: %lu", GetLastError());
		return 1;
	}
	printf(" OK! (flag:%d)", req_verify.is_successful);

	printf("\n[+] Ready! Launching GUI...");
	//FreeConsole();
	kita::kita_instance("bad-echo", 300, 500)
		.callbacks(on_pre_render, on_render)
		.position()
		.show()
		.run()
	;	

	return 0;
}