#pragma once

#include <Windows.h>
#include <winternl.h>

inline decltype(NtDeviceIoControlFile) * _NtDeviceIoControlFile = nullptr;
