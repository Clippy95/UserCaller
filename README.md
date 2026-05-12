# UserCaller

UserCaller is a small x86-only C++ library for calling and hooking functions that use non-standard register-based ABIs, especially the kinds of `__usercall` signatures often seen in reverse-engineered code.

It uses JIT-generated thunks to bridge between normal C++ `__cdecl` code and custom target conventions. The project currently targets 32-bit x86 only.

## What It Solves

Normal C++ code expects ordinary ABI rules:

- integer and pointer arguments usually arrive on the stack
- scalar floating-point returns usually come back in `st0`
- plain function pointers have a fixed calling convention

Reverse-engineered game and engine code often does something else:

- arguments in `eax`, `ecx`, `edx`, `esi`, `edi`, or `ebx`
- scalar floating-point arguments in `xmm` registers
- returns in `eax`, `edx:eax`, `st0`, or `xmm0`
- caller-clean or callee-clean stack behavior depending on the target

UserCaller lets you describe that target ABI in templates and get back a normal callable C++ wrapper.

## Core Idea

UserCaller has three main thunk directions:

1. `uc::make<...>(target)`
   Wraps one fixed target address in a normal C++ callable object.

2. `uc::make_invoker<...>()`
   Builds one shared thunk for a signature and lets you pass the target address at call time.

3. `uc::make_callback<...>(callback_fn)`
   Builds the reverse bridge so foreign code can call a normal C++ callback through a weird register ABI.

Internally, each of these emits x86 machine code with AsmJit and stores the result in executable memory.

## Supported ABI Pieces

### Argument locations

- `uc::eax_arg<T>`
- `uc::ebx_arg<T>`
- `uc::ecx_arg<T>`
- `uc::edx_arg<T>`
- `uc::esi_arg<T>`
- `uc::edi_arg<T>`
- `uc::stack_arg<T>`
- `uc::xmm0_arg<T>` through `uc::xmm7_arg<T>`

### Return locations

- `uc::void_ret<void>`
- `uc::eax_ret<T>`
- `uc::edx_eax_ret<long long>`
- `uc::st0_ret<float>` / `uc::st0_ret<double>`
- `uc::xmm0_ret<float>` / `uc::xmm0_ret<double>`

### Cleanup modes

- `uc::cleanup::caller`
- `uc::cleanup::callee`

## Current Type Rules

- GPR register args (`eax`/`ebx`/`ecx`/`edx`/`esi`/`edi`) must be 4 bytes or smaller.
- Stack args may be up to 8 bytes.
- `edx:eax` return is supported for 64-bit integral or enum values.
- `st0` return is supported for `float` and `double`.
- `xmm` args are supported for scalar `float` and `double` only.
- `xmm0` return is supported for scalar `float` and `double` only.

Not supported right now:

- x64
- structs/classes by value
- `__m128` / packed vector ABI support
- aggregate returns
- duplicate use of the same non-stack argument register in one signature

## Basic Usage

### 1. Wrap a fixed target address

```cpp
auto fn = uc::make<
    uc::eax_ret<int>,
    uc::edx_arg<int>
>(target_address);

int result = fn(7);
```

This means:

- the target returns `int` in `eax`
- the target expects its argument in `edx`
- your C++ code still calls it like a normal function

### 2. Use a shared invoker

```cpp
auto invoker = uc::make_invoker<
    uc::eax_ret<int>,
    uc::edx_arg<int>
>();

int result = invoker(target_address, 7);
```

This is useful when many functions share the same ABI shape.

### 3. Use the `abi` helper to avoid repeating templates

```cpp
using target_abi = uc::abi<
    uc::eax_ret<int>,
    uc::edx_arg<int>
>;

auto fn = target_abi::make(target_address);
auto invoker = target_abi::make_invoker();
```

`uc::abi<...>` bundles:

- `ret_t`
- `invoker_t`
- `callback_fn_t`
- `function_t`
- `function_callee_t`
- `callback_t`
- `callback_callee_t`

and exposes factory helpers for each.

## Callbacks

`uc::make_callback()` builds a JIT stub that looks like the foreign ABI on the outside, but calls a normal C++ `__cdecl` function on the inside.

Example:

```cpp
float __cdecl MyCallback(float value)
{
    return value * 3.0f;
}

auto cb = uc::make_callback<
    uc::xmm0_ret<float>,
    uc::xmm1_arg<float>
>(&MyCallback);

void* foreign_fn_ptr = cb.raw();
```

That stub:

- receives the incoming arg from `xmm1`
- repackages it into a normal C++ stack call
- calls `MyCallback`
- converts the C++ `st0` float return into `xmm0`
- returns to the foreign caller

The callback object owns the executable stub memory, so keep it alive as long as foreign code may call it.

## Scalar SSE Support

UserCaller now supports scalar SSE bridging for x86:

- `xmm0`-`xmm7` arguments
- `xmm0` return
- `float` and `double` only

This is important because the public C++ side is still ordinary x86 `__cdecl`, which does not naturally match a usercall-like SSE ABI.

### What the thunk does for SSE targets

When you call:

```cpp
auto fn = uc::make<
    uc::xmm0_ret<float>,
    uc::xmm1_arg<float>
>(target);
```

the generated thunk:

1. receives the C++ argument from the stack
2. loads it into `xmm1`
3. calls the target
4. reads the target's `xmm0` return
5. converts that return back to `st0`
6. returns to the normal C++ caller

### What the thunk does for SSE callbacks

When you build:

```cpp
auto cb = uc::make_callback<
    uc::xmm0_ret<float>,
    uc::xmm1_arg<float>
>(&MyCallback);
```

the generated callback stub:

1. receives the foreign arg from `xmm1`
2. spills it onto the stack as a normal C++ argument
3. calls the `__cdecl` callback
4. takes the callback's `st0` return
5. moves that result into `xmm0`
6. returns to the foreign caller

## Cleanup Semantics

The cleanup mode describes who removes stack-passed target arguments:

- `uc::make<...>()` and `uc::make_invoker<...>()` default to caller-clean
- `uc::make_callee<...>()` and `uc::make_invoker_callee<...>()` are for callee-clean targets
- `uc::make_callback_callee<...>()` creates callback stubs that return with stack cleanup

For stack arguments, UserCaller emits the appropriate `add esp, ...` or `ret N` behavior based on that mode.

## `patch_call`

UserCaller also includes a simple helper for patching an existing `E8 rel32` call instruction:

```cpp
uc::patch_call(call_site, new_target);
```

This:

- verifies the first byte is `0xE8`
- temporarily changes page protection with `VirtualProtect`
- writes the new relative target
- restores protection
- flushes the instruction cache

It is intentionally small and only handles direct x86 `call rel32` sites.

## Optional SafetyHook Integration

SafetyHook integration is intentionally kept out of the core header. It lives in:

- `usercaller/safetyhook_inline.hpp`

To enable it, define:

```cpp
#define UC_WITH_SAFETYHOOK 1
```

before including the optional header, and make sure `safetyhook.hpp` is available on the include path.

### Why the wrapper exists

SafetyHook is responsible for:

- patching the target function
- creating the trampoline
- enabling/disabling/resetting the inline hook

UserCaller is responsible for:

- converting between the target ABI and normal C++ callback ABI
- calling the trampoline through the correct usercall ABI

That means `uc::inline_hook<Abi>` does not use SafetyHook's `call()` helpers for the original function. Instead it does:

1. `callback_ = Abi::make_callback(callback)`
2. `invoker_ = Abi::make_invoker()`
3. `hook_ = safetyhook::create_inline(target, callback_.raw())`
4. `call_original(args...)` calls `invoker_(hook_.trampoline().address(), args...)`

This is the key point that makes SafetyHook usable with non-standard usercall layouts.

### Example

```cpp
using target_abi = uc::abi<
    uc::eax_ret<int>,
    uc::edx_arg<int>
>;

static uc::inline_hook<target_abi> g_hook;

int __cdecl Hook_Target(int value)
{
    int og = g_hook.call_original(value);
    return og * 4;
}

void install()
{
    g_hook.create(reinterpret_cast<void*>(target_addr), &Hook_Target);
}
```

## How the Generated Thunks Work Internally

At a high level, each thunk:

1. creates a stable x86 frame with `ebp`
2. reads incoming C++ arguments from stack slots
3. marshals them into the target ABI:
   - pushes stack args right-to-left
   - moves integer/pointer args into GPRs
   - loads scalar FP args into `xmm` registers when requested
4. calls either:
   - a baked target address
   - a runtime `target` parameter
   - a normal C++ callback function
5. fixes up cleanup according to the descriptor
6. bridges return values if needed:
   - `eax` returns naturally
   - `edx:eax` returns naturally
   - `st0` returns naturally
   - `xmm0 -> st0` for normal C++ callers
   - `st0 -> xmm0` for foreign SSE callback callers

The executable code is stored in a `detail::code_block`, which frees the JIT allocation when the last owner goes away.

## Files

- `UserCaller/usercaller/usercaller.hpp`
  Public API and ABI description types.

- `UserCaller/usercaller/usercaller.cpp`
  JIT thunk generation and low-level patch helpers.

- `UserCaller/usercaller/safetyhook_inline.hpp`
  Optional SafetyHook inline-hook wrapper.

- `UserCaller/tests/test.cpp`
  Example targets and runtime validation coverage.

## Running the Test App

The solution contains a small console test program that exercises:

- GPR argument passing
- stack arguments
- caller-clean and callee-clean conventions
- 64-bit `edx:eax` returns
- `st0` float/double returns
- scalar `xmm` float/double argument and return bridging
- callback bridging
- optional SafetyHook inline hooking

Build the Win32 target and run the generated `UserCaller.exe`.

## Practical Notes

- Keep callback objects alive while native code may still call them.
- Use `abi<...>` when you expect to create both callbacks and invokers for the same signature.
- Use `make_invoker()` for trampoline/original calls where only the target address changes.
- Treat `xmm` support as scalar-only for now. If you need `__m128` or larger vector ABI support, that should be added as a separate feature.
