#ifndef CORE_LIBS_PRX_LIBC_INCLUDE_GENERAL_ASMMACROS_HPP
#define CORE_LIBS_PRX_LIBC_INCLUDE_GENERAL_ASMMACROS_HPP

#ifdef _WIN32
#define APS5_ASM_FUNCTION(name) ".globl " name "\n.def " name "; .scl 2; .type 32; .endef\n" name ":\n"
#define APS5_ASM_CALL(name) "    call " name "\n"
#elif defined(__APPLE__)
#define APS5_ASM_FUNCTION(name) ".globl _" name "\n_" name ":\n"
#define APS5_ASM_CALL(name) "    call _" name "\n"
#else
#define APS5_ASM_FUNCTION(name) ".globl " name "\n.type " name ", @function\n" name ":\n"
#define APS5_ASM_CALL(name) "    call " name "\n"
#endif

#endif
