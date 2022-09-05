#pragma once
/*
	* API Monitor Dump reference
	* create file call:
	* #	Time of Day	Thread	Module	API	Return Value	Error	Duration
	* 134	1:07:15.632 AM	1	KERNELBASE.dll	NtCreateFile ( 0x000000444f5df320, FILE_READ_ATTRIBUTES | GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, 0x000000444f5df378, 0x000000444f5df338, NULL, 0x00000000, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0x00000000 )	STATUS_SUCCESS		0.0000200
	* 
	* ioctl call:
	* #	Time of Day	Thread	Module	API	Return Value	Error	Duration
	* 137	1:07:15.664 AM	1	KERNELBASE.dll	NtDeviceIoControlFile ( 0x00000000000003dc, NULL, NULL, NULL, 0x000000444f5df520, 0x252e5e08, 0x000000444f5df5d0, 0x00000018, 0x000000444f5df5d0, 0x00000018 )	STATUS_SUCCESS		0.0000030
	*/

#include <cstdint>
#include <Windows.h>
#include <winternl.h>
#include <memory>
#include "global.hpp"

namespace echo
{
	constexpr char SRV_NAME[]      = "EchoDrv";
	constexpr char SYS_FILE_NAME[] = "EchoDrv.sys";

	inline SC_HANDLE service_handle = nullptr;
	inline HANDLE    device_handle  = nullptr;

	enum class CODES_IOCTL_REQUEST : DWORD
	{
		// method flag -                          0000 0000 0000 0000 0000 0000 0000 0011
		// access flag -                          0000 0000 0000 0000 1100 0000 0000 0000
		VERIFY_SIGNATURE         = 0x9E6A0594, // 1001 1110 0110 1010 0000 0101 1001 0100
		CREATE_PROCESS_HANDLE    = 0xE6224248, // 1110 0110 0010 0010 0100 0010 0100 1000
		READ_MEMORY              = 0x60A26124, // 0110 0000 1010 0010 0110 0001 0010 0100
		QUERY_MEMORY             = 0x85360588, // 1000 0101 0011 0110 0000 0101 1000 1000
		SETUP_OBREGISTER_PROTECT = 0x252E5E08, // 0010 0101 0010 1110 0101 1110 0000 1000
		PROTECT_PROCESS          = 0x25F26648, // 0010 0101 1111 0010 0110 0110 0100 1000
		UNPROTECT_PROCESS        = 0xE273849C, // 1110 0010 0111 0011 1000 0100 1001 1100
	};

	#define ECHO_DECL_IOCTL_REQ(name, code) \
		struct __attribute__((packed)) __impl_##name  { enum : DWORD { IOCTL_CODE = (DWORD)CODES_IOCTL_REQUEST::code }; }; \
		struct __attribute__((packed)) name : public __impl_##name

	ECHO_DECL_IOCTL_REQ(req_read_memory, READ_MEMORY)
	{
		HANDLE proc_handle;
		void * read_address;
		void * read_buffer;
		std::uint64_t buffer_size;
		std::uint64_t bytes_read_out;
		DWORD is_successful;
		std::uint32_t unk0;
	};

	ECHO_DECL_IOCTL_REQ(req_proc_open, CREATE_PROCESS_HANDLE)
	{
		DWORD pid;
		DWORD desired_access;
		HANDLE handle_out;
		DWORD is_successful;
		std::uint32_t unk0;
	};

	ECHO_DECL_IOCTL_REQ(req_verify_signature, VERIFY_SIGNATURE)
	{
		PUCHAR pb_sig;
		ULONG cb_sig;
		char pad[4];
		DWORD is_successful;
		std::uint32_t unk0; 
	};

	
	ECHO_DECL_IOCTL_REQ(req_obrcb_protect, SETUP_OBREGISTER_PROTECT)
	{
		DWORD pid_protect;
		DWORD pid_white_list[3];
		DWORD is_successful;
		DWORD self_proc_id;
	};

	ECHO_DECL_IOCTL_REQ(req_proc_protect, PROTECT_PROCESS)
	{
		DWORD pid;
		DWORD prot_flag; // set to 2 or 1
		DWORD is_successful;
		std::uint32_t unk2;
	};

	ECHO_DECL_IOCTL_REQ(req_proc_unprotect, UNPROTECT_PROCESS)
	{
		DWORD pid;
		DWORD old_flag;
		DWORD is_successful;
		std::uint32_t unk2;
	};

	#undef ECHO_DECL_IOCTL_REQ

	constexpr DWORD INVALID_REQUEST = (DWORD)-1;

	template <typename req_t>
	auto ioctl_request(req_t & in, req_t * out, CODES_IOCTL_REQUEST code) -> DWORD
	{
		#if 0
		DWORD count = 0;
		if (!DeviceIoControl(device_handle, (DWORD)code, &in, sizeof(req_t), (out ?: &in), sizeof(req_t), &count, nullptr))
			return INVALID_REQUEST;
		#endif
		IO_STATUS_BLOCK iosb {};
		if (!NT_SUCCESS(_NtDeviceIoControlFile(device_handle, NULL, NULL, NULL, &iosb, (ULONG)code, &in, sizeof(req_t), (out ?: &in), sizeof(req_t))))
			return INVALID_REQUEST;
		return (DWORD)iosb.Information;
	}

	template <typename req_t>
	auto ioctl_request(req_t & in, req_t * out = nullptr) -> DWORD
	{
		static_assert(requires { req_t::IOCTL_CODE; }, "req_t does not contain an IOCTL_CODE field to be used.");
		return ioctl_request(in, out, (CODES_IOCTL_REQUEST)req_t::IOCTL_CODE);
	}
}
