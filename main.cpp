#include "native.h"

namespace Rtl
{
	ULONG GetProcessCookie() {
		ULONG procCookie = 0;
		NtQueryInformationProcess(CurrentProcess, ProcessCookie, &procCookie, 4, 0);
		return procCookie;
	}

	PVOID EncodePointer(PVOID ptr) {
		u64 uPtr = (u64)ptr;
		ULONG cookie = GetProcessCookie();
		return (PVOID)__ROR8__(uPtr ^ cookie, cookie & 0x3F);
	}

	PVOID DecodePointer(PVOID encodedPtr) {
		u64 uEncoded = (u64)encodedPtr;
		ULONG cookie = GetProcessCookie();
		uEncoded = __ROL8__(uEncoded, cookie & 0x3F);
		return (pv)(uEncoded ^= cookie);
	}

	int walkVehList() {
		PLDR_VECTOR_HANDLER_LIST vehHandlerList = (PLDR_VECTOR_HANDLER_LIST)RVA((u64)RtlAddVectoredExceptionHandler + 0x121, 7);
		if (vehHandlerList->vehList->Flink == vehHandlerList->vehList) return 0;
		int vehCnt = 0;
		PLDR_VECTOR_HANDLER_ENTRY head = (PLDR_VECTOR_HANDLER_ENTRY)vehHandlerList->vehList;
		PLDR_VECTOR_HANDLER_ENTRY curr = (PLDR_VECTOR_HANDLER_ENTRY)head;
		do {
			vehCnt++;
			printf("[%p] Blink %p, Flink %p, EncodedPtr %p => Decode %p\n", curr, curr->listEntry.Blink, curr->listEntry.Flink, curr->EncodedPtr, Rtl::DecodePointer(curr->EncodedPtr));
			curr = (PLDR_VECTOR_HANDLER_ENTRY)curr->listEntry.Flink;
		} while (curr != head && (u64)curr != (u64)&vehHandlerList->vehList);
		return vehCnt;
	}
}

void TestHandler1() {
	return Sleep(0x98765);
}

void TestHandler2() {
	return Sleep(0x43210);
	
}

int main()
{
	PVOID handler1 = AddVectoredExceptionHandler(0, (PVECTORED_EXCEPTION_HANDLER)TestHandler1);
	PVOID handler2 = AddVectoredExceptionHandler(0, (PVECTORED_EXCEPTION_HANDLER)TestHandler2);
	printf("VectoredHandler1:0x%p\tVectoredHandler2:0x%p\n\n", handler1, handler2);
	int cnt = Rtl::walkVehList();
	printf("process has %d veh.\n", cnt);
}
