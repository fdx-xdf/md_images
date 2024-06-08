## 背景知识
在之前的文章中，我们介绍了静态欺骗和动态欺骗堆栈，今天我们来一起学习一下另一种技术，它被它的作者称为Custom Call Stacks,即自定义堆栈调用。
关于堆栈欺骗的背景我们就不再说了，这里我们补充一下回调函数和 windows 线程池的知识。
回调函数是指向函数的指针，该函数可以传递给要在其中执行的其他函数，在常规的 shellcode loader 中回调函数也是一种常见的执行方式，并且 github 上有仓库详细的记录了各种各样的回调函数执行 shellcode：[https://github.com/aahmad097/AlternativeShellcodeExec](https://github.com/aahmad097/AlternativeShellcodeExec)。
但是这种执行回调的方式都存在一个问题，回调方和调用方位于同一个线程中，假设当我们通过回调LoadLibrary 时，执行此时的堆栈就像是这样`LoadLibrary returns to -> Callback Function returns to -> RX region`，RX region 指的是我们的 shellcode 地址，所以我们的 shellcode 的内存空间很容易被发现。
为了解决这个问题，我们要用到 windows 线程池，官方介绍如下：Windows线程池是一种操作系统提供的机制，用于管理和调度多个工作线程，以提高多线程应用程序的性能和效率。线程池通过重用现有的线程来执行任务，避免了频繁创建和销毁线程的开销，从而提升系统资源利用率和应用程序的响应速度。
其实就是提前给我们创建好了很多线程，让我们可以方便的进行调度，当有任务需要执行时，我们提交给线程池就可以了。
## 参数如何传递
下面是一个小 demo
```cpp
#include <windows.h>
#include <stdio.h>

int main() {
    CHAR *libName = "wininet.dll";

    PTP_WORK WorkReturn = NULL;
    TpAllocWork(&WorkReturn, LoadLibraryA, libName, NULL); // pass `LoadLibraryA` as a callback to TpAllocWork
    TpPostWork(WorkReturn);                                // request Allocated Worker Thread Execution
    TpReleaseWork(WorkReturn);                             // worker thread cleanup

    WaitForSingleObject((HANDLE)-1, 1000);
    printf("hWininet: %p\n", GetModuleHandleA(libName)); //check if library is loaded

    return 0;
}
```
让 gpt 来帮我们解释一下代码：

1. **TpAllocWork(&WorkReturn, LoadLibraryA, libName, NULL);**：这行代码使用了**TpAllocWork**函数来分配一个工作项，将**LoadLibraryA**函数作为回调函数，以异步的方式加载指定名称的动态链接库。**LoadLibraryA**是用于加载ANSI字符串（即**CHAR**类型）的动态链接库函数。
2. **TpPostWork(WorkReturn);**：这行代码将分配的工作项提交给线程池，请求线程池中的工作线程执行加载库的任务。
3. **TpReleaseWork(WorkReturn);**：这行代码释放了分配的工作项，进行了工作线程的清理操作。

可以看到，通过这种方式确实帮助我们在一个新的线程执行了 LoadLibraryA 函数，但是能不能成功执行呢？
如果编译上面的代码，那么代码将会崩溃，因为他的参数传递并不正确。
TpAllocWork 的定义是：
```cpp
NTSTATUS NTAPI TpAllocWork(
    PTP_WORK* ptpWrk,
    PTP_WORK_CALLBACK pfnwkCallback,
    PVOID OptionalArg,
    PTP_CALLBACK_ENVIRON CallbackEnvironment
);
```
这意味着我们的回调函数 LoadLibraryA 应该是 PTP_WORK_CALLBACK 类型。此类型扩展为：
```cpp
VOID CALLBACK WorkCallback(
PTP_CALLBACK_INSTANCE Instance,
PVOID Context,
PTP_WORK Work
);
```
从上图中可以看出，我们的 OptionalArg作为辅助参数转发到我们的 Callback （ PVOID Context ）。因此，如果我们的假设是正确的，那么我们传递给 TpAllocWork 的参数 libName (wininet.dll) 最终将作为我们 LoadLibraryA 的第二个参数。在 x64dbg 中检查此项会导致下图：
![image.png](https://cdn.nlark.com/yuque/0/2024/png/40360538/1716285913414-1132dd7a-090c-449d-aa58-819d73743d5c.png#averageHue=%23f1e7df&clientId=u91e2ceee-79cd-4&from=paste&height=294&id=ud918b381&originHeight=441&originWidth=2560&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=371306&status=done&style=none&taskId=ud9d21103-5b5e-45f7-bf1e-f81a826f312&title=&width=1706.6666666666667)
还记得上篇文章中关于 64 位下传递参数的规则吗，rcx 应该存第一个参数，rdx 中应该存第二个参数。
## 直接在WorkCallback 中执行
但是不要放弃，还是有希望的，我们直接在上面的WorkCallback 中让它执行就可以了，如下面的代码所示：
```cpp
#include <windows.h>
#include <stdio.h>

VOID CALLBACK WorkCallback(
_Inout_     PTP_CALLBACK_INSTANCE Instance,
_Inout_opt_ PVOID                 Context,
_Inout_     PTP_WORK              Work
) {
    LoadLibraryA(Context);
}

int main() {
    CHAR *libName = "wininet.dll";

    PTP_WORK WorkReturn = NULL;
    TpAllocWork(&WorkReturn, WorkerCallback, libName, NULL); // pass `LoadLibraryA` as a callback to TpAllocWork
    TpPostWork(WorkReturn);                                // request Allocated Worker Thread Execution
    TpReleaseWork(WorkReturn);                             // worker thread cleanup

    WaitForSingleObject((HANDLE)-1, 1000);
    printf("hWininet: %p\n", GetModuleHandleA(libName)); //check if library is loaded

    return 0;
}
```
但是这样的话，回调相当于在我们 shellcode 的内存区域执行的，我们的堆栈变成了`LoadLibraryA returns to -> Callback in RX Region returns to -> RtlUserThreadStart -> TpPostWork`，这样并不好，因为归根结底还是出现了 shellcode 的内存区域。
## 借助汇编跳转执行
但是不要放弃，我们还有别的机会来进行尝试，我们可以通过汇编来帮助我们调整堆栈结构，只需要在汇编里面 mov rdx，rcx，再 jmp 到 LoadLibraryA 的位置就可以了，注意这里是 jmp 而不是 call，如果 call 的话我们会先将此时的地址压入堆栈，再去执行，这样堆栈中还是会出现 shellcode 的内存区域，但是我们 jmp 的话，就直接过去了，我们的汇编函数并没有在堆栈留下任何痕迹，这也是一个小技巧。
代码如下：
```cpp
#include <windows.h>
#include <stdio.h>

typedef NTSTATUS (NTAPI* TPALLOCWORK)(PTP_WORK* ptpWrk, PTP_WORK_CALLBACK pfnwkCallback, PVOID OptionalArg, PTP_CALLBACK_ENVIRON CallbackEnvironment);
typedef VOID (NTAPI* TPPOSTWORK)(PTP_WORK);
typedef VOID (NTAPI* TPRELEASEWORK)(PTP_WORK);

FARPROC pLoadLibraryA;

UINT_PTR getLoadLibraryA() {
    return (UINT_PTR)pLoadLibraryA;
}

extern VOID CALLBACK WorkCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);

int main() {
    pLoadLibraryA = GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA");
    FARPROC pTpAllocWork = GetProcAddress(GetModuleHandleA("ntdll"), "TpAllocWork");
    FARPROC pTpPostWork = GetProcAddress(GetModuleHandleA("ntdll"), "TpPostWork");
    FARPROC pTpReleaseWork = GetProcAddress(GetModuleHandleA("ntdll"), "TpReleaseWork");

    CHAR *libName = "wininet.dll";
    PTP_WORK WorkReturn = NULL;
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallback, libName, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);

    WaitForSingleObject((HANDLE)-1, 0x1000);
    printf("hWininet: %p\n", GetModuleHandleA(libName));

    return 0;
}
```
我们的汇编函数如下：
```
section .text

extern getLoadLibraryA

global WorkCallback

WorkCallback:
    mov rcx, rdx
    xor rdx, rdx
    call getLoadLibraryA
    jmp rax
```
触发回调时执行WorkCallback 函数，然后在WorkCallback 我们手动调整参数位置，然后`call getLoadLibraryA`，获得LoadLibraryA 的内存地址，然后直接 jmp 过去，这就是我们所完成的事情。
现在看一下我们的堆栈，十分完美：
![image.png](https://cdn.nlark.com/yuque/0/2024/png/40360538/1716287060056-81d637f3-9040-471b-bac0-c298cd876cc8.png#averageHue=%23f8f0e4&clientId=u91e2ceee-79cd-4&from=paste&height=655&id=udd005cc0&originHeight=982&originWidth=2560&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=842016&status=done&style=none&taskId=u8bedda1b-e8a9-4fe7-94b2-1359a7a7440&title=&width=1706.6666666666667)
## 多参数调用
现在我们要考虑一些其他的问题了，比如参数个数，如果参数个数超过 4 个我们是要存放在堆栈中的，以NtAllocateVirtualMemory 为例，它的定义是：
```cpp
__kernel_entry NTSYSCALLAPI NTSTATUS NtAllocateVirtualMemory(
  [in]      HANDLE    ProcessHandle,
  [in, out] PVOID     *BaseAddress,
  [in]      ULONG_PTR ZeroBits,
  [in, out] PSIZE_T   RegionSize,
  [in]      ULONG     AllocationType,
  [in]      ULONG     Protect
);
```
我们现在需要将 NtAllocateVirtualMemory 的指针及其结构内的参数传递给回调，以便我们的回调可以从结构中提取这些信息并执行它。忽略掉 ZeroBits (值恒为 0)和 AllocationType（值为0x3000），我们可以得到一个新的结构体，定义如下
```cpp
typedef struct _NTALLOCATEVIRTUALMEMORY_ARGS {
    UINT_PTR pNtAllocateVirtualMemory;   // pointer to NtAllocateVirtualMemory - rax
    HANDLE hProcess;                     // HANDLE ProcessHandle - rcx
    PVOID* address;                      // PVOID *BaseAddress - rdx; ULONG_PTR ZeroBits - 0 - r8
    PSIZE_T size;                        // PSIZE_T RegionSize - r9; ULONG AllocationType - MEM_RESERVE|MEM_COMMIT = 3000 - stack pointer
    ULONG permissions;                   // ULONG Protect - PAGE_EXECUTE_READ - 0x20 - stack pointer
} NTALLOCATEVIRTUALMEMORY_ARGS, *PNTALLOCATEVIRTUALMEMORY_ARGS;
```
然后我们的代码和上面也差不多
```cpp
#include <windows.h>
#include <stdio.h>

typedef NTSTATUS (NTAPI* TPALLOCWORK)(PTP_WORK* ptpWrk, PTP_WORK_CALLBACK pfnwkCallback, PVOID OptionalArg, PTP_CALLBACK_ENVIRON CallbackEnvironment);
typedef VOID (NTAPI* TPPOSTWORK)(PTP_WORK);
typedef VOID (NTAPI* TPRELEASEWORK)(PTP_WORK);

typedef struct _NTALLOCATEVIRTUALMEMORY_ARGS {
UINT_PTR pNtAllocateVirtualMemory;   // pointer to NtAllocateVirtualMemory - rax
HANDLE hProcess;                     // HANDLE ProcessHandle - rcx
PVOID* address;                      // PVOID *BaseAddress - rdx; ULONG_PTR ZeroBits - 0 - r8
PSIZE_T size;                        // PSIZE_T RegionSize - r9; ULONG AllocationType - MEM_RESERVE|MEM_COMMIT = 3000 - stack pointer
ULONG permissions;                   // ULONG Protect - PAGE_EXECUTE_READ - 0x20 - stack pointer
} NTALLOCATEVIRTUALMEMORY_ARGS, *PNTALLOCATEVIRTUALMEMORY_ARGS;

extern VOID CALLBACK WorkCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);

int main() {
    LPVOID allocatedAddress = NULL;
    SIZE_T allocatedsize = 0x1000;

    NTALLOCATEVIRTUALMEMORY_ARGS ntAllocateVirtualMemoryArgs = { 0 };
    ntAllocateVirtualMemoryArgs.pNtAllocateVirtualMemory = (UINT_PTR) GetProcAddress(GetModuleHandleA("ntdll"), "NtAllocateVirtualMemory");
    ntAllocateVirtualMemoryArgs.hProcess = (HANDLE)-1;
    ntAllocateVirtualMemoryArgs.address = &allocatedAddress;
    ntAllocateVirtualMemoryArgs.size = &allocatedsize;
    ntAllocateVirtualMemoryArgs.permissions = PAGE_EXECUTE_READ;

    FARPROC pTpAllocWork = GetProcAddress(GetModuleHandleA("ntdll"), "TpAllocWork");
    FARPROC pTpPostWork = GetProcAddress(GetModuleHandleA("ntdll"), "TpPostWork");
    FARPROC pTpReleaseWork = GetProcAddress(GetModuleHandleA("ntdll"), "TpReleaseWork");

    PTP_WORK WorkReturn = NULL;
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallback, &ntAllocateVirtualMemoryArgs, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);

    WaitForSingleObject((HANDLE)-1, 0x1000);
    printf("allocatedAddress: %p\n", allocatedAddress);
    getchar();

    return 0;
}
```
重点是我们汇编传递参数的部分参数，调用回调函数 WorkCallback 时，我们的堆栈顶部是 TppWorkpExecuteCallback 的返回值。
![](https://cdn.nlark.com/yuque/0/2024/png/40360538/1716291616058-06e554bd-31f3-4ea2-beea-60ede3f54fea.png#averageHue=%23f0e5dc&clientId=u86ffa87f-85dd-4&from=paste&id=uddc4884f&originHeight=438&originWidth=968&originalType=url&ratio=1.5&rotation=0&showTitle=false&status=done&style=none&taskId=u00a89942-1646-4eb6-8ec4-1ff3c8d834d&title=)
如果在的堆栈顶部修改返回地址，并向其添加参数，则整个堆栈帧将发生混乱，从而导致 WorkCallback 函数无法正常返回。因此，我们必须在不更改堆栈帧本身的情况下修改堆栈。因此我们只能直接修改堆栈的值，TppWorkpExecuteCallback 的堆栈是可以容下我们参数所需要的栈的，下面是作者给的汇编代码：
```
section .text

global WorkCallback

WorkCallback:
    mov rbx, rdx                ; backing up the struct as we are going to stomp rdx
    mov rax, [rbx]              ; NtAllocateVirtualMemory
    mov rcx, [rbx + 0x8]        ; HANDLE ProcessHandle
    mov rdx, [rbx + 0x10]       ; PVOID *BaseAddress
    xor r8, r8                  ; ULONG_PTR ZeroBits
    mov r9, [rbx + 0x18]        ; PSIZE_T RegionSize
    mov r10, [rbx + 0x20]       ; ULONG Protect
    mov [rsp+0x30], r10         ; stack pointer for 6th arg
    mov r10, 0x3000             ; ULONG AllocationType
    mov [rsp+0x28], r10         ; stack pointer for 5th arg
    jmp rax
```
堆栈也是非常干净
![](https://cdn.nlark.com/yuque/0/2024/png/40360538/1716292266212-cad403e0-fcdf-475b-930b-333313530dae.png#averageHue=%23fbf2e7&clientId=u86ffa87f-85dd-4&from=paste&id=ub95ff23c&originHeight=997&originWidth=2516&originalType=url&ratio=1.5&rotation=0&showTitle=false&status=done&style=none&taskId=u74be0007-4617-4a5c-8eb5-910208341df&title=)
## 总结
当然还有其他的利用方式，这里也不再一一列举，我们还需要思考的问题是除了TpAllocWork TpPostWork TpReleaseWork这一组  api，还有没有其他的 api 可以利用，这里推荐一个项目：
[https://github.com/fin3ss3g0d/IoDllProxyLoad](https://github.com/fin3ss3g0d/IoDllProxyLoad)
另外这种方式可不可以和 syscall 结合到一起，推荐项目：
[https://github.com/pard0p/CallstackSpoofingPOC/tree/main](https://github.com/pard0p/CallstackSpoofingPOC/tree/main)
