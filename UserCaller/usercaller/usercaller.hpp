#pragma once

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <type_traits>
#include <vector>

#if !defined(_M_IX86) && !defined(__i386__)
#error UserCaller currently supports only 32-bit x86 builds.
#endif

#if defined(_MSC_VER)
#define UC_CDECL __cdecl
#else
#define UC_CDECL
#endif

namespace uc
{
    enum class loc : std::uint8_t
    {
        none,
        stack,
        eax,
        ebx,
        ecx,
        edx,
        esi,
        edi,

        st0,
    };

    enum class loc_pair : std::uint8_t
    {
        none,
        edx_eax,
    };

    enum class cleanup : std::uint8_t
    {
        caller,
        callee,
    };

    template <loc Where, typename T>
    struct arg
    {
        using type = T;
        static constexpr loc where = Where;
    };

    template <loc Where, typename T>
    struct ret
    {
        using type = T;
        static constexpr bool is_pair = false;
        static constexpr loc where = Where;
        static constexpr loc_pair pair_where = loc_pair::none;
    };

    template <loc_pair Where, typename T>
    struct ret64
    {
        using type = T;

        static constexpr bool is_pair = true;
        static constexpr loc where = loc::none;
        static constexpr loc_pair pair_where = Where;
    };

    template <typename T> using eax_ret = ret<loc::eax, T>;
    template <typename T> using void_ret = ret<loc::none, T>;
    template <typename T> using st0_ret = ret<loc::st0, T>;
    template <typename T> using edx_eax_ret = ret64<loc_pair::edx_eax, T>;

    template <typename T> using eax_arg = arg<loc::eax, T>;
    template <typename T> using ebx_arg = arg<loc::ebx, T>;
    template <typename T> using ecx_arg = arg<loc::ecx, T>;
    template <typename T> using edx_arg = arg<loc::edx, T>;
    template <typename T> using esi_arg = arg<loc::esi, T>;
    template <typename T> using edi_arg = arg<loc::edi, T>;
    template <typename T> using stack_arg = arg<loc::stack, T>;

    namespace detail
    {
        struct arg_desc
        {
            loc where{};
            std::uint32_t bytes{};
        };

        struct abi_desc
        {
            cleanup cleanup_mode{};
            loc return_where{};
            std::uint32_t return_bytes{};
            bool runtime_target{};
            std::vector<arg_desc> args{};
        };

        struct code_block
        {
            explicit code_block(void* entry_) noexcept;
            ~code_block() noexcept;

            code_block(const code_block&) = delete;
            code_block& operator=(const code_block&) = delete;

            void* entry{};
        };

        std::shared_ptr<code_block> build_baked(const abi_desc& desc, std::uintptr_t target);
        std::shared_ptr<code_block> build_invoker(const abi_desc& desc);

        template <typename T>
        consteval std::uint32_t abi_bytes()
        {
            if constexpr (std::is_void_v<T>)
            {
                return 0;
            }
            else
            {
                static_assert(sizeof(T) <= 8, "UserCaller only supports <= 8-byte args in this first version.");

                if constexpr (sizeof(T) <= 4)
                    return 4;
                else
                    return 8;
            }
        }

        template <typename ArgSpec>
        consteval bool valid_arg()
        {
            using T = typename ArgSpec::type;

            if constexpr (ArgSpec::where == loc::stack)
            {
                return sizeof(T) <= 8;
            }
            else
            {
                constexpr loc w = ArgSpec::where;

                constexpr bool is_gpr =
                    w == loc::eax ||
                    w == loc::ebx ||
                    w == loc::ecx ||
                    w == loc::edx ||
                    w == loc::esi ||
                    w == loc::edi;

                return is_gpr && sizeof(T) <= 4;
            }
        }

        template <typename RetSpec>
        consteval bool valid_ret()
        {
            using T = typename RetSpec::type;

            if constexpr (RetSpec::is_pair)
            {
                return
                    RetSpec::pair_where == loc_pair::edx_eax &&
                    sizeof(T) == 8 &&
                    (std::is_integral_v<T> || std::is_enum_v<T>);
            }
            else
            {
                if constexpr (std::is_void_v<T>)
                {
                    return RetSpec::where == loc::none;
                }
                else if constexpr (RetSpec::where == loc::eax)
                {
                    return sizeof(T) <= 4;
                }
                else if constexpr (RetSpec::where == loc::st0)
                {
                    return std::is_same_v<T, float> || std::is_same_v<T, double>;
                }
                else
                {
                    return false;
                }
            }
        }

        template <loc Where, typename... ArgSpecs>
        consteval int count_arg_loc()
        {
            return ((ArgSpecs::where == Where ? 1 : 0) + ... + 0);
        }

        template <typename... ArgSpecs>
        consteval bool no_duplicate_register_args()
        {
            return
                count_arg_loc<loc::eax, ArgSpecs...>() <= 1 &&
                count_arg_loc<loc::ebx, ArgSpecs...>() <= 1 &&
                count_arg_loc<loc::ecx, ArgSpecs...>() <= 1 &&
                count_arg_loc<loc::edx, ArgSpecs...>() <= 1 &&
                count_arg_loc<loc::esi, ArgSpecs...>() <= 1 &&
                count_arg_loc<loc::edi, ArgSpecs...>() <= 1;
        }

        template <cleanup CleanupMode, bool RuntimeTarget, typename RetSpec, typename... ArgSpecs>
        abi_desc make_desc()
        {
            static_assert(valid_ret<RetSpec>(), "Only void return, <=4-byte eax return, st0 float/double return, or edx:eax int64 return is supported for now.");
            static_assert((valid_arg<ArgSpecs>() && ...), "Invalid arg. Register args must be <=4 bytes. Stack args may be <=8 bytes.");

            static_assert(
                no_duplicate_register_args<ArgSpecs...>(),
                "Duplicate register arguments are not allowed. Only stack arguments may repeat."
                );

            abi_desc desc{};
            desc.cleanup_mode = CleanupMode;
            desc.return_where = RetSpec::where;
            desc.return_bytes = abi_bytes<typename RetSpec::type>();
            desc.runtime_target = RuntimeTarget;

            desc.args = {
                arg_desc{
                    ArgSpecs::where,
                    abi_bytes<typename ArgSpecs::type>()
                }...
            };

            return desc;
        }

        template <cleanup CleanupMode, typename RetSpec, typename... ArgSpecs>
        struct invoker_cache
        {
            using ret_t = typename RetSpec::type;
            using fn_t = ret_t(UC_CDECL*)(std::uintptr_t target, typename ArgSpecs::type...);

            static fn_t get()
            {
                static std::shared_ptr<code_block> block =
                    build_invoker(make_desc<CleanupMode, true, RetSpec, ArgSpecs...>());

                return reinterpret_cast<fn_t>(block->entry);
            }
        };
    }

    template <cleanup CleanupMode, typename RetSpec, typename... ArgSpecs>
    class function
    {
    public:
        using ret_t = typename RetSpec::type;
        using fn_t = ret_t(UC_CDECL*)(typename ArgSpecs::type...);

        explicit function(std::uintptr_t target)
        {
            auto desc = detail::make_desc<CleanupMode, false, RetSpec, ArgSpecs...>();
            block_ = detail::build_baked(desc, target);
            fn_ = reinterpret_cast<fn_t>(block_->entry);
        }

        function(const function&) = default;
        function& operator=(const function&) = default;

        function(function&&) noexcept = default;
        function& operator=(function&&) noexcept = default;

        ret_t operator()(typename ArgSpecs::type... args) const
        {
            if constexpr (std::is_void_v<ret_t>)
            {
                fn_(args...);
            }
            else
            {
                return fn_(args...);
            }
        }

        fn_t raw() const noexcept
        {
            return fn_;
        }

    private:
        std::shared_ptr<detail::code_block> block_{};
        fn_t fn_{};
    };

    template <typename RetSpec, typename... ArgSpecs>
    auto make(std::uintptr_t target)
    {
        return function<cleanup::caller, RetSpec, ArgSpecs...>(target);
    }

    template <typename RetSpec, typename... ArgSpecs>
    auto make_callee(std::uintptr_t target)
    {
        return function<cleanup::callee, RetSpec, ArgSpecs...>(target);
    }

    template <typename RetSpec, typename... ArgSpecs>
    auto make_invoker()
    {
        return detail::invoker_cache<cleanup::caller, RetSpec, ArgSpecs...>::get();
    }

    template <typename RetSpec, typename... ArgSpecs>
    auto make_invoker_callee()
    {
        return detail::invoker_cache<cleanup::callee, RetSpec, ArgSpecs...>::get();
    }
}