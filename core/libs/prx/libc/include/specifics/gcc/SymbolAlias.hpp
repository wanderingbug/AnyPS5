#ifndef CORE_LIBS_PRX_LIBC_INCLUDE_GCC_SYMBOLALIAS_HPP
#define CORE_LIBS_PRX_LIBC_INCLUDE_GCC_SYMBOLALIAS_HPP

#if defined(__linux__)
#define GCC_LOCAL_ALIAS(alias, target) \
    asm(".local " #alias "\n.set " #alias "," #target "\n")
#define GCC_GLOBAL_ALIAS(alias, target) \
    asm(".globl " #alias "\n.set " #alias "," #target "\n")
#elif defined(__APPLE__)
#define GCC_LOCAL_ALIAS(alias, target) \
    asm(".private_extern _" #alias "\n.set _" #alias ", _" #target "\n")
#define GCC_GLOBAL_ALIAS(alias, target) \
    asm(".globl _" #alias "\n.set _" #alias ", _" #target "\n")
#else
#define GCC_LOCAL_ALIAS(alias, target)
#define GCC_GLOBAL_ALIAS(alias, target)
#endif

#define GCC_HIDDEN_FN

#endif
