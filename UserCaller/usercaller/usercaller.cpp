#include "usercaller.hpp"

#include <asmjit/x86.h>

#include <mutex>
#include <string>

namespace uc::detail
{
    namespace
    {
        asmjit::JitRuntime& runtime()
        {
            static asmjit::JitRuntime rt;
            return rt;
        }

        std::mutex& runtime_mutex()
        {
            static std::mutex mtx;
            return mtx;
        }

        [[noreturn]] void throw_asmjit_error(const char* what, asmjit::Error err)
        {
            throw std::runtime_error(
                std::string("UserCaller: ") +
                what +
                ": " +
                asmjit::DebugUtils::error_as_string(err)
            );
        }

        asmjit::x86::Gp gp_from_loc(loc where)
        {
            using namespace asmjit;

            switch (where)
            {
            case loc::eax: return x86::eax;
            case loc::ebx: return x86::ebx;
            case loc::ecx: return x86::ecx;
            case loc::edx: return x86::edx;
            case loc::esi: return x86::esi;
            case loc::edi: return x86::edi;
            default:
                throw std::runtime_error("UserCaller: invalid register location.");
            }
        }

        bool uses_register(const abi_desc& desc, loc reg)
        {
            for (const auto& arg : desc.args)
            {
                if (arg.where == reg)
                    return true;
            }

            return false;
        }

        std::uint32_t pushed_stack_bytes(const abi_desc& desc)
        {
            std::uint32_t total = 0;

            for (const auto& arg : desc.args)
            {
                if (arg.where == loc::stack)
                    total += arg.bytes;
            }

            return total;
        }

        std::vector<std::uint32_t> wrapper_arg_offsets(const abi_desc& desc)
        {
            std::vector<std::uint32_t> offsets;
            offsets.reserve(desc.args.size());

            // Baked wrapper:
            // [ebp + 8] = arg0
            //
            // Runtime invoker:
            // [ebp + 8]  = target
            // [ebp + 12] = arg0
            std::uint32_t offset = desc.runtime_target ? 12u : 8u;

            for (const auto& arg : desc.args)
            {
                offsets.push_back(offset);
                offset += arg.bytes;
            }

            return offsets;
        }

        void emit_push_stack_arg(
            asmjit::x86::Assembler& a,
            const arg_desc& arg,
            std::uint32_t wrapper_offset)
        {
            using namespace asmjit;

            if (arg.bytes == 4)
            {
                a.push(x86::dword_ptr(x86::ebp, static_cast<int>(wrapper_offset)));
                return;
            }

            if (arg.bytes == 8)
            {
                // x86 stack is little-endian.
                // For an 8-byte argument at [ebp+offset]:
                //
                // low32  = [ebp+offset]
                // high32 = [ebp+offset+4]
                //
                // To place it correctly for the callee, push high then low.
                a.push(x86::dword_ptr(x86::ebp, static_cast<int>(wrapper_offset + 4)));
                a.push(x86::dword_ptr(x86::ebp, static_cast<int>(wrapper_offset)));
                return;
            }

            throw std::runtime_error("UserCaller: unsupported stack arg size.");
        }

        void emit_thunk_body(
            asmjit::x86::Assembler& a,
            const abi_desc& desc,
            std::uintptr_t baked_target)
        {
            using namespace asmjit;

            const auto offsets = wrapper_arg_offsets(desc);

            const bool preserve_ebx = uses_register(desc, loc::ebx);
            const bool preserve_esi = uses_register(desc, loc::esi);
            const bool preserve_edi = uses_register(desc, loc::edi);

            const bool baked = !desc.runtime_target;

            // Standard frame keeps wrapper arg offsets stable even after pushes.
            a.push(x86::ebp);
            a.mov(x86::ebp, x86::esp);

            // For baked calls, keep the target in a local stack slot.
            // This avoids clobbering eax/ecx/edx just to call the target.
            //
            // [ebp - 4] = target address
            if (baked)
            {
                a.sub(x86::esp, 4);
                a.mov(
                    x86::dword_ptr(x86::ebp, -4),
                    static_cast<std::uint32_t>(baked_target)
                );
            }

            if (preserve_ebx)
                a.push(x86::ebx);

            if (preserve_esi)
                a.push(x86::esi);

            if (preserve_edi)
                a.push(x86::edi);

            // Push target stack args right-to-left.
            for (std::size_t i = desc.args.size(); i > 0; --i)
            {
                const std::size_t index = i - 1;
                const auto& arg = desc.args[index];

                if (arg.where == loc::stack)
                    emit_push_stack_arg(a, arg, offsets[index]);
            }

            // Load register args after stack pushes.
            for (std::size_t i = 0; i < desc.args.size(); ++i)
            {
                const auto& arg = desc.args[i];

                if (arg.where == loc::stack)
                    continue;

                if (arg.bytes != 4)
                    throw std::runtime_error("UserCaller: register args must be 4 bytes in this version.");

                a.mov(
                    gp_from_loc(arg.where),
                    x86::dword_ptr(x86::ebp, static_cast<int>(offsets[i]))
                );
            }

            if (desc.runtime_target)
            {
                // Runtime invoker signature:
                // ret __cdecl invoker(uintptr_t target, args...)
                //
                // [ebp + 8] = target
                a.call(x86::dword_ptr(x86::ebp, 8));
            }
            else
            {
                // Baked target lives at [ebp - 4].
                a.call(x86::dword_ptr(x86::ebp, -4));
            }

            const std::uint32_t stack_bytes = pushed_stack_bytes(desc);

            if (desc.cleanup_mode == cleanup::caller && stack_bytes != 0)
                a.add(x86::esp, stack_bytes);

            if (preserve_edi)
                a.pop(x86::edi);

            if (preserve_esi)
                a.pop(x86::esi);

            if (preserve_ebx)
                a.pop(x86::ebx);

            // Removes baked local slot too, if it exists.
            a.mov(x86::esp, x86::ebp);
            a.pop(x86::ebp);
            a.ret();
        }

        void* build_code(const abi_desc& desc, std::uintptr_t baked_target)
        {
            using namespace asmjit;

            JitRuntime& rt = runtime();

            CodeHolder code;
            Error err = code.init(rt.environment(), rt.cpu_features());

            if (err != Error::kOk)
                throw_asmjit_error("CodeHolder::init failed", err);

            x86::Assembler a(&code);

            emit_thunk_body(a, desc, baked_target);

            void* fn = nullptr;

            {
                std::lock_guard<std::mutex> lock(runtime_mutex());

                err = rt.add(&fn, &code);
            }

            if (err != Error::kOk)
                throw_asmjit_error("JitRuntime::add failed", err);

            return fn;
        }
    }

    code_block::code_block(void* entry_) noexcept
        : entry(entry_)
    {
    }

    code_block::~code_block() noexcept
    {
        if (!entry)
            return;

        std::lock_guard<std::mutex> lock(runtime_mutex());
        runtime().release(entry);
        entry = nullptr;
    }

    std::shared_ptr<code_block> build_baked(const abi_desc& desc, std::uintptr_t target)
    {
        if (desc.runtime_target)
            throw std::runtime_error("UserCaller: build_baked received runtime-target descriptor.");

        return std::make_shared<code_block>(build_code(desc, target));
    }

    std::shared_ptr<code_block> build_invoker(const abi_desc& desc)
    {
        if (!desc.runtime_target)
            throw std::runtime_error("UserCaller: build_invoker received baked-target descriptor.");

        return std::make_shared<code_block>(build_code(desc, 0));
    }
}