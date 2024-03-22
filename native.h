#pragma once 
#pragma warning(disable:4996)
#define PHNT_VERSION PHNT_THRESHOLD
#include <phnt_windows.h>
#include <phnt.h>
#include <TlHelp32.h>
#include <stdint.h>
#include <stdio.h>
#pragma comment(lib, "ntdll.lib")

#define DbgPrintf(fmt, ...) printf("[%s] " fmt, __FUNCTION__, __VA_ARGS__);

typedef unsigned long long u64;
typedef unsigned long u32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef void* pv;
typedef unsigned long long QWORD;
#define RVA(Instr, InstrSize) ((DWORD64)Instr + InstrSize + *(LONG*)((DWORD64)Instr + (InstrSize - sizeof(LONG))))
#define GET_NT_HEADERS(baseAddress) (PIMAGE_NT_HEADERS)((uint64_t)baseAddress + (PIMAGE_DOS_HEADER(baseAddress))->e_lfanew)
#define GET_IMAGE_SIZE(baseAddress) ((PIMAGE_NT_HEADERS)((uint64_t)baseAddress + (PIMAGE_DOS_HEADER(baseAddress))->e_lfanew))->OptionalHeader.SizeOfImage
#define ROUNDUP(n, step) (((n) + (step) - 1) / (step)) * (step)
#define CurrentProcess ((HANDLE)-1)
#define CurrentThread ((HANDLE)-2)

// rotate left
template<class T> T __ROL__(T value, int count)
{
	const unsigned int nbits = sizeof(T) * 8;

	if (count > 0)
	{
		count %= nbits;
		T high = value >> (nbits - count);
		if (T(-1) < 0) // signed value
			high &= ~((T(-1) << count));
		value <<= count;
		value |= high;
	}
	else
	{
		count = -count % nbits;
		T low = value << (nbits - count);
		value >>= count;
		value |= low;
	}
	return value;
}

inline u8  __ROL1__(u8  value, int count) { return __ROL__((u8)value, count); }
inline u16 __ROL2__(u16 value, int count) { return __ROL__((u16)value, count); }
inline u32 __ROL4__(u32 value, int count) { return __ROL__((u32)value, count); }
inline u64 __ROL8__(u64 value, int count) { return __ROL__((u64)value, count); }
inline u8  __ROR1__(u8  value, int count) { return __ROL__((u8)value, -count); }
inline u16 __ROR2__(u16 value, int count) { return __ROL__((u16)value, -count); }
inline u32 __ROR4__(u32 value, int count) { return __ROL__((u32)value, -count); }
inline u64 __ROR8__(u64 value, int count) { return __ROL__((u64)value, -count); }

typedef struct _LDR_VECTOR_HANDLER_LIST {
	PSRWLOCK vehLock; // a3 == 0
	PLIST_ENTRY vehList;
	PSRWLOCK vchLock; // a3 == 1 
	PLIST_ENTRY vchList;
}LDR_VECTOR_HANDLER_LIST, * PLDR_VECTOR_HANDLER_LIST;

typedef struct _LDR_VECTOR_HANDLER_ENTRY {
	LIST_ENTRY listEntry; // 0x0
	u64* always1; // 0x10 point to heap
	u64 zero;
	PVOID EncodedPtr;
}LDR_VECTOR_HANDLER_ENTRY, * PLDR_VECTOR_HANDLER_ENTRY;