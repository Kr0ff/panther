#pragma once

#include <Windows.h>
#include <iostream>
#include <stdarg.h>

#include <Shlwapi.h>
#include <Psapi.h>
#include <tchar.h>

#define STATUS_SUCCESS                          ((NTSTATUS)0x00000000L) // ntsubauth

#include "gate_structs.h"

#pragma comment(lib, "shlwapi.lib")