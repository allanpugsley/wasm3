//
//  m3_config_platforms.h
//
//  Created by Volodymyr Shymanskyy on 11/20/19.
//  Copyright © 2019 Volodymyr Shymanskyy. All rights reserved.
//

#ifndef m3_config_platforms_h
#define m3_config_platforms_h

#include "wasm3_defs.h"

/*
 * Internal helpers
 */

# if !defined(__cplusplus) || defined(_MSC_VER)
#   define not      !
#   define and      &&
#   define or       ||
# endif

/*
 * Detect/define features
 */

# if defined(M3_COMPILER_MSVC)
#  include <stdint.h>
#  if UINTPTR_MAX == 0xFFFFFFFF
#   define M3_SIZEOF_PTR 4
#  elif UINTPTR_MAX == 0xFFFFFFFFFFFFFFFFu
#   define M3_SIZEOF_PTR 8
#  else
#   error "Pointer size not supported"
#  endif
# elif defined(__SIZEOF_POINTER__)
#  define M3_SIZEOF_PTR __SIZEOF_POINTER__
#else
#  error "Pointer size not detected"
# endif

# if defined(M3_BIG_ENDIAN)
#  define M3_BSWAP_u8(X)  {}
#  define M3_BSWAP_u16(X) { (X)=m3_bswap16((X)); }
#  define M3_BSWAP_u32(X) { (X)=m3_bswap32((X)); }
#  define M3_BSWAP_u64(X) { (X)=m3_bswap64((X)); }
#  define M3_BSWAP_i8(X)  {}
#  define M3_BSWAP_i16(X) M3_BSWAP_u16(X)
#  define M3_BSWAP_i32(X) M3_BSWAP_u32(X)
#  define M3_BSWAP_i64(X) M3_BSWAP_u64(X)
#  define M3_BSWAP_f32(X) { union { f32 f; u32 i; } u; u.f = (X); M3_BSWAP_u32(u.i); (X) = u.f; }
#  define M3_BSWAP_f64(X) { union { f64 f; u64 i; } u; u.f = (X); M3_BSWAP_u64(u.i); (X) = u.f; }
# else
#  define M3_BSWAP_u8(X)  {}
#  define M3_BSWAP_u16(x) {}
#  define M3_BSWAP_u32(x) {}
#  define M3_BSWAP_u64(x) {}
#  define M3_BSWAP_i8(X)  {}
#  define M3_BSWAP_i16(X) {}
#  define M3_BSWAP_i32(X) {}
#  define M3_BSWAP_i64(X) {}
#  define M3_BSWAP_f32(X) {}
#  define M3_BSWAP_f64(X) {}
# endif

# if defined(M3_COMPILER_GCC) || defined(M3_COMPILER_CLANG) || defined(M3_COMPILER_ICC)
#  define UNLIKELY(x) __builtin_expect(!!(x), 0)
#  define LIKELY(x)   __builtin_expect(!!(x), 1)
# else
#  define UNLIKELY(x) (x)
#  define LIKELY(x)   (x)
# endif


# if defined(M3_COMPILER_MSVC)
#  define M3_WEAK //__declspec(selectany)
# elif defined(__MINGW32__)
#  define M3_WEAK //__attribute__((selectany))
# else
#  define M3_WEAK __attribute__((weak))
# endif

# ifndef M3_MIN
#  define M3_MIN(A,B) (((A) < (B)) ? (A) : (B))
# endif
# ifndef M3_MAX
#  define M3_MAX(A,B) (((A) > (B)) ? (A) : (B))
# endif

#define M3_INIT(field) memset(&field, 0, sizeof(field))

#define M3_COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))

#if defined(__AVR__)

# define PRIu64         "llu"
# define PRIi64         "lli"

# define d_m3ShortTypesDefined
typedef double          f64;
typedef float           f32;
typedef uint64_t        u64;
typedef int64_t         i64;
typedef uint32_t        u32;
typedef int32_t         i32;
typedef short unsigned  u16;
typedef short           i16;
typedef uint8_t         u8;
typedef int8_t          i8;

#endif

/*
 * Apply settings
 */

# if defined (M3_COMPILER_MSVC)
#   define vectorcall   // For MSVC, better not to specify any call convention
# elif defined(__MINGW32__)
#   define vectorcall
# elif defined(WIN32)
#   define vectorcall   __vectorcall
# elif defined (ESP8266)
#   include <c_types.h>
#   define op_section   //ICACHE_FLASH_ATTR
# elif defined (ESP32)
#   if defined(M3_IN_IRAM)  // the interpreter is in IRAM, attribute not needed
#     define op_section
#   else
#     include "esp_system.h"
#     define op_section   IRAM_ATTR
#   endif
# elif defined (FOMU)
#   define op_section   __attribute__((section(".ramtext")))
# endif

#ifndef vectorcall
#define vectorcall
#endif

#ifndef op_section
#define op_section
#endif


/*
 * Device-specific defaults
 */

# ifndef d_m3MaxFunctionStackHeight
#  if defined(ESP8266) || defined(ESP32) || defined(ARDUINO_AMEBA) || defined(TEENSYDUINO)
#    define d_m3MaxFunctionStackHeight          128
#  endif
# endif

# ifndef d_m3FixedHeap
#  if defined(ARDUINO_AMEBA)
#    define d_m3FixedHeap                       (128*1024)
#  elif defined(BLUE_PILL) || defined(FOMU)
#    define d_m3FixedHeap                       (12*1024)
#  elif defined(ARDUINO_ARCH_ARC32) // Arduino 101
#    define d_m3FixedHeap                       (10*1024)
#  endif
# endif

/*
 * Platform-specific defaults
 */

# if defined(ARDUINO) || defined(PARTICLE) || defined(PLATFORMIO) || defined(__MBED__) || \
     defined(ESP8266) || defined(ESP32) || defined(BLUE_PILL) || defined(WM_W600) || defined(FOMU)
#  ifndef d_m3VerboseErrorMessages
#    define d_m3VerboseErrorMessages            0
#  endif
#  ifndef d_m3MaxFunctionStackHeight
#    define d_m3MaxFunctionStackHeight          64
#  endif
#  ifndef d_m3CodePageAlignSize
#    define d_m3CodePageAlignSize               1024
#  endif
# endif

/*
 * Arch-specific defaults
 */
#if defined(__riscv) && __riscv_xlen == 64
#  ifndef d_m3MaxFunctionStackHeight
#    define d_m3Use32BitSlots                   0
#  endif
#endif

#endif // m3_config_platforms_h
