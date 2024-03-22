### Introduce 
[ <url>https://learn.microsoft.com/ko-kr/windows/win32/debug/vectored-exception-handling</url> ]   
"벡터화된 예외 처리기는 구조화된 예외 처리에 대한 확장입니다. 애플리케이션은 애플리케이션에 대한 모든 예외를 감시하거나 처리하는 함수를 등록할 수 있습니다. 벡터화된 처리기는 프레임 기반이 아니므로 호출 프레임의 위치에 관계없이 호출되는 처리기를 추가할 수 있습니다. 벡터화된 처리기는 디버거가 첫 번째 알림을 받은 후 시스템이 스택 해제를 시작하기 전에 추가된 순서대로 호출됩니다. "

벡터예외 처리기를 등록하면 어떠한 예외처리기보다 먼저 내가 정의한 예외 처리기에서 에러를 핸들링 할 수 있음. 이를 이용한 후킹 방법도 존재하는데 Page_guard hook 이라고 함. 느리지만 어떠한 바이트 패치도 없이 후킹이 가능하단 강점이 존재함 
1) VirtualProtect로 페이지에 Page_guard 속성 부여 
2) 해당 페이지에 access하면 예외발생 
3) 이를 Veh 를 사용해 핸들링함 

그렇다면 프로세스에 veh가 추가됐는지 어떻게 확인할 수 있을까 ? 


### Analysis 

veh는 AddVectoredContinueHandler에 의해 추가된다. 이 함수는 최종적으로 ntdll.RtlpAddVectoredHandler 를 호출한다. 
```c 
__int64 __fastcall RtlAddVectoredExceptionHandler(__int64 first, __int64 handler) {
  return RtlpAddVectoredHandler(first, handler, 0i64);
}
``` 
이 함수를 분석해보자.  LdrpVectorHandlerList라는 심볼이 눈에 띈다. 
```c
_QWORD *__fastcall RtlpAddVectoredHandler(int first, void *handler, unsigned int a3)
{
  __int64 v3; // rbp
  int v6; // ebx
  void *ProcessHeap; // rcx
  __int64 Heap; // rax
  _QWORD *v9; // rbx
  _QWORD *v10; // rax
  unsigned int v11; // ecx
  void **v12; // rdi
  _QWORD *v13; // rax
  int v14; // edx
  bool v15; // zf
  __int64 v16; // rdx
  void ***v18; // rax
  void *v19; // rcx
  NTSTATUS v20; // eax
  __int64 v21; // [rsp+30h] [rbp-28h]
  unsigned int ProcessInformation; // [rsp+78h] [rbp+20h] BYREF

  v3 = a3;
  if ( (int)LdrEnsureMrdataHeapExists() >= 0 && ((int)RtlQueryProtectedPolicy(&unk_180123268) < 0 || !v21) )
  {
    if ( (unsigned int)LdrControlFlowGuardEnforced() )
    {
      RtlAcquireSRWLockExclusive(&LdrpMrdataLock);
      v6 = *(_DWORD *)LdrpMrdataHeapUnprotected;
      if ( !*(_DWORD *)LdrpMrdataHeapUnprotected )
        RtlProtectHeap(LdrpMrdataHeap, 0i64);
      if ( v6 == 0xFFFFFFFF )
        goto LABEL_39;
      *(_DWORD *)LdrpMrdataHeapUnprotected = v6 + 1;
      RtlReleaseSRWLockExclusive(&LdrpMrdataLock);
    }
    if ( (unsigned int)LdrControlFlowGuardEnforced() )
      ProcessHeap = (void *)LdrpMrdataHeap;
    else
      ProcessHeap = NtCurrentPeb()->ProcessHeap;
    Heap = RtlAllocateHeap(ProcessHeap, 0i64, 0x28i64);
    v9 = (_QWORD *)Heap;
    if ( !Heap )
    {
LABEL_19:
      if ( !(unsigned int)LdrControlFlowGuardEnforced() )
        return v9;
      RtlAcquireSRWLockExclusive(&LdrpMrdataLock);
      v14 = *(_DWORD *)LdrpMrdataHeapUnprotected;
      if ( *(_DWORD *)LdrpMrdataHeapUnprotected )
      {
        v15 = v14 == 1;
        v16 = (unsigned int)(v14 - 1);
        *(_DWORD *)LdrpMrdataHeapUnprotected = v16;
        if ( v15 )
        {
          LOBYTE(v16) = 1;
          RtlProtectHeap(LdrpMrdataHeap, v16);
        }
        RtlReleaseSRWLockExclusive(&LdrpMrdataLock);
        return v9;
      }
LABEL_39:
      RtlReleaseSRWLockExclusive(&LdrpMrdataLock);
      __fastfail(0xEu);
    }
    *(_DWORD *)(Heap + 0x18) = 0;
    v10 = (_QWORD *)RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, 0i64, 8i64);
    v9[2] = v10;
    if ( !v10 )
    {
      if ( (unsigned int)LdrControlFlowGuardEnforced() )
        v19 = (void *)LdrpMrdataHeap;
      else
        v19 = NtCurrentPeb()->ProcessHeap;
      RtlFreeHeap(v19, 0i64, v9);
      v9 = 0i64;
      goto LABEL_19;
    }
    v11 = `RtlpGetCookieValue'::`2'::CookieValue;
    *v10 = 1i64;
    if ( !v11 )
    {
      v20 = NtQueryInformationProcess(
              (HANDLE)0xFFFFFFFFFFFFFFFFi64,
              (PROCESSINFOCLASS)0x24,
              &ProcessInformation,
              4u,
              0i64);
      if ( v20 < 0 )
        RtlRaiseStatus((unsigned int)v20);
      v11 = ProcessInformation;
      `RtlpGetCookieValue'::`2'::CookieValue = ProcessInformation;
    }
    v9[4] = __ROR8__((unsigned __int64)handler ^ v11, v11 & 0x3F);
    v12 = &LdrpVectorHandlerList + 3 * v3 + 1;
    LdrProtectMrdata(0i64);
    RtlAcquireSRWLockExclusive(*(&LdrpVectorHandlerList + 3 * v3));
    if ( *v12 == v12 )
      _interlockedbittestandset((volatile signed __int32 *)&NtCurrentPeb()->80, v3 + 2);
    if ( first )
    {
      v13 = *v12;
      if ( *((void ***)*v12 + 1) == v12 )
      {
        *v9 = v13;
        v9[1] = v12;
        v13[1] = v9;
        *v12 = v9;
LABEL_18:
        RtlReleaseSRWLockExclusive(*(&LdrpVectorHandlerList + 3 * v3));
        LdrProtectMrdata(1i64);
        goto LABEL_19;
      }
    }
    else
    {
      v18 = (void ***)v12[1];
      if ( *v18 == v12 )
      {
        *v9 = v12;
        v9[1] = v18;
        *v18 = (void **)v9;
        v12[1] = v9;
        goto LABEL_18;
      }
    }
    __fastfail(3u);
  }
  return 0i64;
}
``` 

```c
 Heap = RtlAllocateHeap(ProcessHeap, 0i64, 0x28i64);
``` 
먼저 0x28 사이즈의 힙을 생성하고 여기에 값을 채워넣는다. ( 변수명 v9 = Heap ) 
그럼 v9[0], [1], [2], [3], [4]엔 어떤 값이 들어갈까 ? <br></br>
```c
 if ( first )
    {
      v13 = *v12;
      if ( *((void ***)*v12 + 1) == v12 )
      {
        *v9 = v13;
        v9[1] = v12;
        v13[1] = v9;
        *v12 = v9;
``` 
이 부분은 Linked-List를 만드는 부분으로 예측할 수 있다.  <br></br>
```c 
v10 = (_QWORD *)RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, 0i64, 8i64);
v9[2] = v10;
*v10 = 1i64;
``` 
이 부분을 보면 *v9[2] 값은 항상 1이다. <br></br>
```c
*(_DWORD *)(Heap + 0x18) = 0;
``` 
v9[3] = 0 

마지막으로 가장 중요한 v[4]이다. 
v[4]에는 호출시에 전달했던 사용자 정의 Handler의 주소가 들어가는데, 
```c
	v20 = NtQueryInformationProcess(
              (HANDLE)0xFFFFFFFFFFFFFFFFi64,
              (PROCESSINFOCLASS)0x24,
              &ProcessInformation,
              4u,
              0i64);
      if ( v20 < 0 )
        RtlRaiseStatus((unsigned int)v20);
      v11 = ProcessInformation;
      `RtlpGetCookieValue'::`2'::CookieValue = ProcessInformation;
    }
    v9[4] = __ROR8__((unsigned __int64)handler ^ v11, v11 & 0x3F);
```
위처럼 프로세스의 쿠키정보를 사용해서 인코딩하여 저장한다. 다시 디코딩하지 않고서는 핸들러의 값을 파악할 수 없다.<br></br>
또 handler entry를 handler list에 삽입하기 위해선 이 list에 대한 Lock을 획득하여야 한다.
```c 
RtlAcquireSRWLockExclusive(*(&LdrpVectorHandlerList + 3 * v3));
``` 
v3 = 0, 1이 될 수 있는데 이는 LdrpVectorHandlerList 구조체의 첫번째와 세번째 멤버는 각 리스트에 대한 SRWLock을 구현함을 알 수 있다.    
(v3==0일땐 Vectored Exception Handler, v3==1일땐 Vectored Continue Handler) 

위 정보들을 취합해서 구조체를 정의하자. 
```c 
typedef struct _LDR_VECTOR_HANDLER_LIST {
	PSRWLOCK vehLock; // a3 == 0
	PLIST_ENTRY vehList; 
	PSRWLOCK vchLock; // a3 == 1 
	PLIST_ENTRY vchList;
}LDR_VECTOR_HANDLER_LIST, *PLDR_VECTOR_HANDLER_LIST;

typedef struct _LDR_VECTOR_HANDLER_ENTRY {
	LIST_ENTRY listEntry; // 0x0
	u64* always1; // 0x10 point to heap
	u64 zero;
	PVOID EncodedPtr; 
}LDR_VECTOR_HANDLER_ENTRY, *PLDR_VECTOR_HANDLER_ENTRY;
```

### credits 
msdn : [ <url>https://learn.microsoft.com/ko-kr/windows/win32/debug/vectored-exception-handling</url> ]   
reactos : [ <url> https://doxygen.reactos.org/d5/d55/vectoreh_8c_source.html </url> ]
