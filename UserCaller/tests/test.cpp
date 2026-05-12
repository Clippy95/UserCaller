#include <cmath>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <Windows.h>

#include "usercaller/usercaller.hpp"

#if __has_include(<safetyhook.hpp>)
#define UC_WITH_SAFETYHOOK 1
#include "usercaller/safetyhook_inline.hpp"
#endif

template <typename Fn>
std::uintptr_t addr_of(Fn fn)
{
    return reinterpret_cast<std::uintptr_t>(fn);
}

void print_addr(const char* name, std::uintptr_t addr)
{
    std::cout
        << std::left << std::setw(40) << std::setfill(' ') << name
        << "0x"
        << std::right
        << std::hex << std::uppercase
        << std::setw(sizeof(std::uintptr_t) * 2)
        << std::setfill('0')
        << addr
        << std::dec << std::nouppercase
        << std::setfill(' ')
        << '\n';
}

void print_pass(const char* name, bool ok)
{
    std::cout << std::left << std::setw(40) << name
        << (ok ? "PASS" : "FAIL")
        << '\n';
}

extern "C" float g_uc_float_value = 12.5f;
extern "C" double g_uc_double_value = 123.25;

// int __usercall Target_Eax_Eax@<eax>(int value@<eax>);
extern "C" __declspec(naked) int Target_Eax_Eax()
{
    __asm
    {
        add eax, 10
        ret
    }
}

// int __usercall Target_Edx_Eax@<eax>(int value@<edx>);
extern "C" __declspec(naked) int Target_Edx_Eax()
{
    __asm
    {
        mov eax, edx
        shl eax, 1
        ret
    }
}

#if defined(UC_WITH_SAFETYHOOK)
using target_abi = uc::abi<
    uc::eax_ret<int>,
    uc::edx_arg<int>
>;

static uc::inline_hook<target_abi> g_Target_Edx_Eax_Hook;

int __cdecl Hook_Target_Edx_Eax(int value)
{
    int og = g_Target_Edx_Eax_Hook.call_original(value);
    return og * 4;
}

void TestInlineHook()
{
    bool ok = g_Target_Edx_Eax_Hook.create(
        reinterpret_cast<void*>(addr_of(&Target_Edx_Eax)),
        &Hook_Target_Edx_Eax
    );

    print_pass("inline hook create", ok);

    auto caller = target_abi::make_invoker();

    int result = caller(addr_of(&Target_Edx_Eax), 7);

    std::cout << "inline hook edx/eax result: "
        << result
        << " expected 56\n";

    print_pass("inline hook edx/eax test", result == 56);
    std::cout << '\n';

    g_Target_Edx_Eax_Hook.reset();
}
#endif

// int __usercall Target_Ecx_Esi_Stack@<eax>(
//     int a@<ecx>,
//     int b@<esi>,
//     int c
// );
extern "C" __declspec(naked) int Target_Ecx_Esi_Stack()
{
    __asm
    {
        mov eax, ecx
        add eax, esi
        add eax, [esp + 4]
        ret
    }
}

// int __usercall Target_CalleeClean@<eax>(
//     int a@<eax>,
//     int b
// );
//
// target cleans b using ret 4
extern "C" __declspec(naked) int Target_CalleeClean()
{
    __asm
    {
        add eax, [esp + 4]
        ret 4
    }
}

// int __usercall Target_Eax_I64Stack@<eax>(
//     int a@<eax>,
//     long long b
// );
extern "C" __declspec(naked) int Target_Eax_I64Stack()
{
    __asm
    {
        // [esp + 4] = b low32
        // [esp + 8] = b high32

        add eax, [esp + 4]
        add eax, [esp + 8]
        ret
    }
}

// long long __usercall Target_I64_Return@<edx:eax>();
extern "C" __declspec(naked) long long Target_I64_Return()
{
    __asm
    {
        mov eax, 0x55667788
        mov edx, 0x11223344
        ret
    }
}

// float __usercall Target_St0_Float@<st0>();
extern "C" __declspec(naked) float Target_St0_Float()
{
    __asm
    {
        fld dword ptr[g_uc_float_value]
        ret
    }
}

// double __usercall Target_St0_Double@<st0>();
extern "C" __declspec(naked) double Target_St0_Double()
{
    __asm
    {
        fld qword ptr[g_uc_double_value]
        ret
    }
}

// int __usercall Target_Eax_Ecx_Edx@<eax>(
//     int a@<eax>,
//     int b@<ecx>,
//     int c@<edx>
// );
extern "C" __declspec(naked) int Target_Eax_Ecx_Edx()
{
    __asm
    {
        add eax, ecx
        add eax, edx
        ret
    }
}

// int __usercall Target_Ebx_Esi_Edi_Clobber@<eax>(
//     int a@<ebx>,
//     int b@<esi>,
//     int c@<edi>
// );
//
// returns a + b + c, then intentionally clobbers ebx/esi/edi.
// UserCaller should restore them before returning to C++.
extern "C" __declspec(naked) int Target_Ebx_Esi_Edi_Clobber()
{
    __asm
    {
        mov eax, ebx
        add eax, esi
        add eax, edi

        mov ebx, 0xAAAAAAAA
        mov esi, 0xBBBBBBBB
        mov edi, 0xCCCCCCCC

        ret
    }
}

// int CheckPreserve_EbxEsiEdi(int(__cdecl* fn)(int, int, int));
//
// This sets ebx/esi/edi to sentinel values, calls the UserCaller thunk,
// then checks that the thunk restored them.
extern "C" __declspec(naked) int CheckPreserve_EbxEsiEdi(int(__cdecl* fn)(int, int, int))
{
    __asm
    {
        push ebx
        push esi
        push edi

        mov ebx, 0x11112222
        mov esi, 0x33334444
        mov edi, 0x55556666

        // after pushing ebx/esi/edi:
        // [esp + 16] = fn
        mov eax, [esp + 16]

        push 3
        push 2
        push 1
        call eax
        add esp, 12

        cmp eax, 6
        jne fail

        cmp ebx, 0x11112222
        jne fail

        cmp esi, 0x33334444
        jne fail

        cmp edi, 0x55556666
        jne fail

        mov eax, 1
        jmp done

        fail :
        xor eax, eax

            done :
        pop edi
            pop esi
            pop ebx
            ret
    }
}

// Tests int __cdecl fn(int, int, int)
// Calls fn(1, 2, 3) many times.
// Expected return = 6.
// Also checks ESP returns to the same value after every call.
extern "C" __declspec(naked) int CheckStackBalance3(
    int(__cdecl* fn)(int, int, int),
    int iterations
)
{
    __asm
    {
        push ebp
        mov  ebp, esp
        sub  esp, 8

        // [ebp - 4] = baseline esp
        // [ebp - 8] = loop counter
        mov[ebp - 4], esp

        mov eax, [ebp + 12]
        mov[ebp - 8], eax

        loop_start :
        cmp dword ptr[ebp - 8], 0
            jle pass

            push 3
            push 2
            push 1

            mov eax, [ebp + 8]  // fn
            call eax

            add esp, 12

            cmp eax, 6
            jne fail

            cmp esp, [ebp - 4]
            jne fail

            dec dword ptr[ebp - 8]
            jmp loop_start

            pass :
        mov eax, 1
            jmp done

            fail :
        xor eax, eax

            done :
        mov esp, ebp
            pop ebp
            ret
    }
}

// Tests int __cdecl fn(int, int)
// Calls fn(10, 20) many times.
// Expected return = 30.
extern "C" __declspec(naked) int CheckStackBalance2(
    int(__cdecl* fn)(int, int),
    int iterations
)
{
    __asm
    {
        push ebp
        mov  ebp, esp
        sub  esp, 8

        mov[ebp - 4], esp

        mov eax, [ebp + 12]
        mov[ebp - 8], eax

        loop_start :
        cmp dword ptr[ebp - 8], 0
            jle pass

            push 20
            push 10

            mov eax, [ebp + 8]
            call eax

            add esp, 8

            cmp eax, 30
            jne fail

            cmp esp, [ebp - 4]
            jne fail

            dec dword ptr[ebp - 8]
            jmp loop_start

            pass :
        mov eax, 1
            jmp done

            fail :
        xor eax, eax

            done :
        mov esp, ebp
            pop ebp
            ret
    }
}

// Tests int __cdecl fn(int, long long)
// Calls fn(5, 0x0000000200000003) many times.
// Expected return = 10.
extern "C" __declspec(naked) int CheckStackBalanceI64Stack(
    int(__cdecl* fn)(int, long long),
    int iterations
)
{
    __asm
    {
        push ebp
        mov  ebp, esp
        sub  esp, 8

        mov[ebp - 4], esp

        mov eax, [ebp + 12]
        mov[ebp - 8], eax

        loop_start :
        cmp dword ptr[ebp - 8], 0
            jle pass

            // fn(5, 0x0000000200000003)
            //
            // cdecl push right-to-left:
            // long long high
            // long long low
            // int a
            push 0x00000002
            push 0x00000003
            push 5

            mov eax, [ebp + 8]
            call eax

            add esp, 12

            cmp eax, 10
            jne fail

            cmp esp, [ebp - 4]
            jne fail

            dec dword ptr[ebp - 8]
            jmp loop_start

            pass :
        mov eax, 1
            jmp done

            fail :
        xor eax, eax

            done :
        mov esp, ebp
            pop ebp
            ret
    }
}

int main()
{
    std::cout << "UserCaller test\n";
    std::cout << "PID: " << GetCurrentProcessId() << "\n\n";

    {
        auto target = addr_of(&Target_Eax_Eax);

        static auto fn = uc::make<
            uc::eax_ret<int>,
            uc::eax_arg<int>
        >(target);

        print_addr("Target_Eax_Eax", target);
        print_addr("UserCaller thunk", addr_of(fn.raw()));

        int result = fn(5);
        std::cout << "eax arg/eax ret: " << result << " expected 15\n\n";
    }

    {
        auto target = addr_of(&Target_Edx_Eax);

        static auto fn = uc::make<
            uc::eax_ret<int>,
            uc::edx_arg<int>
        >(target);

        print_addr("Target_Edx_Eax", target);
        print_addr("UserCaller thunk", addr_of(fn.raw()));

        int result = fn(7);
        std::cout << "edx arg/eax ret: " << result << " expected 14\n\n";
    }

#if defined(UC_WITH_SAFETYHOOK)
    TestInlineHook();
#endif

    {
        auto target = addr_of(&Target_Ecx_Esi_Stack);

        static auto fn = uc::make<
            uc::eax_ret<int>,
            uc::ecx_arg<int>,
            uc::esi_arg<int>,
            uc::stack_arg<int>
        >(target);

        print_addr("Target_Ecx_Esi_Stack", target);
        print_addr("UserCaller thunk", addr_of(fn.raw()));

        int result = fn(1, 2, 3);
        std::cout << "ecx/esi/stack args: " << result << " expected 6\n\n";
    }

    {
        auto target = addr_of(&Target_CalleeClean);

        static auto fn = uc::make_callee<
            uc::eax_ret<int>,
            uc::eax_arg<int>,
            uc::stack_arg<int>
        >(target);

        print_addr("Target_CalleeClean", target);
        print_addr("UserCaller thunk", addr_of(fn.raw()));

        int result = fn(10, 20);
        std::cout << "callee-clean stack arg: " << result << " expected 30\n\n";
    }

    {
        auto target = addr_of(&Target_Eax_I64Stack);

        static auto fn = uc::make<
            uc::eax_ret<int>,
            uc::eax_arg<int>,
            uc::stack_arg<long long>
        >(target);

        print_addr("Target_Eax_I64Stack", target);
        print_addr("UserCaller thunk", addr_of(fn.raw()));

        long long value = 0x0000000200000003LL;
        int result = fn(5, value);

        std::cout << "8-byte stack arg: " << result << " expected 10\n\n";
    }

    {
        auto target = addr_of(&Target_I64_Return);

        static auto fn = uc::make<
            uc::edx_eax_ret<long long>
        >(target);

        print_addr("Target_I64_Return", target);
        print_addr("UserCaller thunk", addr_of(fn.raw()));

        long long result = fn();

        std::cout
            << "edx:eax int64 ret: 0x"
            << std::hex << std::uppercase
            << result
            << std::dec << std::nouppercase
            << " expected 0x1122334455667788\n\n";
    }

    {
        auto target = addr_of(&Target_St0_Float);

        static auto fn = uc::make<
            uc::st0_ret<float>
        >(target);

        print_addr("Target_St0_Float", target);
        print_addr("UserCaller thunk", addr_of(fn.raw()));

        float result = fn();
        bool ok = std::fabs(result - 12.5f) < 0.001f;

        std::cout << "st0 float ret: " << result << " expected 12.5\n";
        print_pass("st0 float test", ok);
        std::cout << '\n';
    }

    {
        auto target = addr_of(&Target_St0_Double);

        static auto fn = uc::make<
            uc::st0_ret<double>
        >(target);

        print_addr("Target_St0_Double", target);
        print_addr("UserCaller thunk", addr_of(fn.raw()));

        double result = fn();
        bool ok = std::fabs(result - 123.25) < 0.000001;

        std::cout << "st0 double ret: " << result << " expected 123.25\n";
        print_pass("st0 double test", ok);
        std::cout << '\n';
    }

    {
        auto target = addr_of(&Target_Eax_Ecx_Edx);

        static auto baked = uc::make<
            uc::eax_ret<int>,
            uc::eax_arg<int>,
            uc::ecx_arg<int>,
            uc::edx_arg<int>
        >(target);

        auto invoker = uc::make_invoker<
            uc::eax_ret<int>,
            uc::eax_arg<int>,
            uc::ecx_arg<int>,
            uc::edx_arg<int>
        >();

        print_addr("Target_Eax_Ecx_Edx", target);
        print_addr("UserCaller baked thunk", addr_of(baked.raw()));
        print_addr("UserCaller shared invoker", addr_of(invoker));

        int baked_result = baked(1, 2, 3);
        int invoker_result = invoker(target, 4, 5, 6);

        std::cout << "eax/ecx/edx baked: " << baked_result << " expected 6\n";
        std::cout << "eax/ecx/edx invoker: " << invoker_result << " expected 15\n\n";
    }

    {
        auto target = addr_of(&Target_Ebx_Esi_Edi_Clobber);

        static auto fn = uc::make<
            uc::eax_ret<int>,
            uc::ebx_arg<int>,
            uc::esi_arg<int>,
            uc::edi_arg<int>
        >(target);

        print_addr("Target_Ebx_Esi_Edi_Clobber", target);
        print_addr("UserCaller thunk", addr_of(fn.raw()));

        int result = fn(1, 2, 3);
        int preserve_ok = CheckPreserve_EbxEsiEdi(fn.raw());

        std::cout << "ebx/esi/edi arg result: " << result << " expected 6\n";
        print_pass("ebx/esi/edi preserve test", preserve_ok != 0);
        std::cout << '\n';
    }

    {
        auto invoker = uc::make_invoker<
            uc::eax_ret<int>,
            uc::eax_arg<int>
        >();

        print_addr("Shared invoker eax/int", addr_of(invoker));
        print_addr("Target_Eax_Eax", addr_of(&Target_Eax_Eax));

        int a = invoker(addr_of(&Target_Eax_Eax), 1);
        int b = invoker(addr_of(&Target_Eax_Eax), 20);

        std::cout << "shared invoker 1: " << a << " expected 11\n";
        std::cout << "shared invoker 2: " << b << " expected 30\n\n";
    }

    auto a = uc::make_invoker<
        uc::eax_ret<int>,
        uc::eax_arg<int>
    >();

    auto b = uc::make_invoker<
        uc::eax_ret<int>,
        uc::eax_arg<int>
    >();

    std::cout << (a == b ? "cache PASS" : "cache FAIL") << "\n";

    constexpr int StressIterations = 1'000'000;

    {
        auto target = addr_of(&Target_Ecx_Esi_Stack);

        static auto fn = uc::make<
            uc::eax_ret<int>,
            uc::ecx_arg<int>,
            uc::esi_arg<int>,
            uc::stack_arg<int>
        >(target);

        int ok = CheckStackBalance3(fn.raw(), StressIterations);

        print_pass("stack balance ecx/esi/stack x1m", ok != 0);
        std::cout << '\n';
    }

    {
        auto target = addr_of(&Target_CalleeClean);

        static auto fn = uc::make_callee<
            uc::eax_ret<int>,
            uc::eax_arg<int>,
            uc::stack_arg<int>
        >(target);

        int ok = CheckStackBalance2(fn.raw(), StressIterations);

        print_pass("stack balance callee-clean x1m", ok != 0);
        std::cout << '\n';
    }

    {
        auto target = addr_of(&Target_Eax_I64Stack);

        static auto fn = uc::make<
            uc::eax_ret<int>,
            uc::eax_arg<int>,
            uc::stack_arg<long long>
        >(target);

        int ok = CheckStackBalanceI64Stack(fn.raw(), StressIterations);

        print_pass("stack balance i64 stack x1m", ok != 0);
        std::cout << '\n';
    }

    {
        auto target = addr_of(&Target_Eax_Ecx_Edx);

        static auto fn = uc::make<
            uc::eax_ret<int>,
            uc::eax_arg<int>,
            uc::ecx_arg<int>,
            uc::edx_arg<int>
        >(target);

        int ok = CheckStackBalance3(fn.raw(), StressIterations);

        print_pass("stack balance eax/ecx/edx x1m", ok != 0);
        std::cout << '\n';
    }

    std::cout << "Process is still alive.\n";
    std::cout << "Attach debugger / inspect memory now.\n";
    std::cout << "Press ENTER to exit, or close the window.\n";



    std::cin.get();

    return 0;
}
