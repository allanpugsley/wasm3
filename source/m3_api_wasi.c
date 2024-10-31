//
//  m3_api_wasi.c
//
//  Created by Volodymyr Shymanskyy on 11/20/19.
//  Copyright © 2019 Volodymyr Shymanskyy. All rights reserved.
//

#define _POSIX_C_SOURCE 200809L

#include "m3_api_wasi.h"

#include "m3_env.h"
#include "m3_exception.h"

#ifdef __APPLE__
#include <TargetConditionals.h>
#if TARGET_OS_IPHONE
#include "ios_error.h"
#include <sys/time.h>
#include <dirent.h>
#endif
#endif

#if defined(d_m3HasWASI)

// Fixup wasi_core.h
#if defined (M3_COMPILER_MSVC)
#  define _Static_assert(...)
#  define __attribute__(...)
#  define _Noreturn
#endif

#include "extra/wasi_core.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>

#if defined(APE)
// Actually Portable Executable
// All functions are already included in cosmopolitan.h
#elif defined(__wasi__) || defined(__APPLE__) || defined(__ANDROID_API__) || defined(__OpenBSD__) || defined(__linux__) || defined(__EMSCRIPTEN__) || defined(__CYGWIN__)
#  include <unistd.h>
#  include <sys/uio.h>
#  if defined(__APPLE__)
#      include <TargetConditionals.h>
#      if TARGET_OS_OSX // TARGET_OS_MAC includes iOS
#          include <sys/random.h>
#      else // iOS / Simulator
#          include <Security/Security.h>
#      endif
#  else
#      include <sys/random.h>
#  endif
#  define HAS_IOVEC
#elif defined(_WIN32)
#  include <Windows.h>
#  include <io.h>
// See http://msdn.microsoft.com/en-us/library/windows/desktop/aa387694.aspx
#  define SystemFunction036 NTAPI SystemFunction036
#  include <NTSecAPI.h>
#  undef SystemFunction036
#  define ssize_t SSIZE_T

#  define open  _open
#  define read  _read
#  define write _write
#  define close _close
#endif

static m3_wasi_context_t* wasi_context;

typedef struct wasi_iovec_t
{
    __wasi_size_t buf;
    __wasi_size_t buf_len;
} wasi_iovec_t;

#define PREOPEN_CNT   5

typedef struct Preopen {
    int         fd;
    const char* path;
    const char* real_path;
} Preopen;

Preopen preopen[PREOPEN_CNT] = {
    {  0, "<stdin>" , "" },
    {  1, "<stdout>", "" },
    {  2, "<stderr>", "" },
    { -1, "/"       , "." },
    { -1, "./"      , "." },
};

#if defined(APE)
#  define APE_SWITCH_BEG
#  define APE_SWITCH_END          {}
#  define APE_CASE_RET(e1,e2)     if (errnum == e1)    return e2;   else
#else
#  define APE_SWITCH_BEG          switch (errnum) {
#  define APE_SWITCH_END          }
#  define APE_CASE_RET(e1,e2)     case e1:   return e2;   break;
#endif

static
__wasi_errno_t errno_to_wasi(int errnum) {
    APE_SWITCH_BEG
    APE_CASE_RET( EPERM   , __WASI_ERRNO_PERM   )
    APE_CASE_RET( ENOENT  , __WASI_ERRNO_NOENT  )
    APE_CASE_RET( ESRCH   , __WASI_ERRNO_SRCH   )
    APE_CASE_RET( EINTR   , __WASI_ERRNO_INTR   )
    APE_CASE_RET( EIO     , __WASI_ERRNO_IO     )
    APE_CASE_RET( ENXIO   , __WASI_ERRNO_NXIO   )
    APE_CASE_RET( E2BIG   , __WASI_ERRNO_2BIG   )
    APE_CASE_RET( ENOEXEC , __WASI_ERRNO_NOEXEC )
    APE_CASE_RET( EBADF   , __WASI_ERRNO_BADF   )
    APE_CASE_RET( ECHILD  , __WASI_ERRNO_CHILD  )
    APE_CASE_RET( EAGAIN  , __WASI_ERRNO_AGAIN  )
    APE_CASE_RET( ENOMEM  , __WASI_ERRNO_NOMEM  )
    APE_CASE_RET( EACCES  , __WASI_ERRNO_ACCES  )
    APE_CASE_RET( EFAULT  , __WASI_ERRNO_FAULT  )
    APE_CASE_RET( EBUSY   , __WASI_ERRNO_BUSY   )
    APE_CASE_RET( EEXIST  , __WASI_ERRNO_EXIST  )
    APE_CASE_RET( EXDEV   , __WASI_ERRNO_XDEV   )
    APE_CASE_RET( ENODEV  , __WASI_ERRNO_NODEV  )
    APE_CASE_RET( ENOTDIR , __WASI_ERRNO_NOTDIR )
    APE_CASE_RET( EISDIR  , __WASI_ERRNO_ISDIR  )
    APE_CASE_RET( EINVAL  , __WASI_ERRNO_INVAL  )
    APE_CASE_RET( ENFILE  , __WASI_ERRNO_NFILE  )
    APE_CASE_RET( EMFILE  , __WASI_ERRNO_MFILE  )
    APE_CASE_RET( ENOTTY  , __WASI_ERRNO_NOTTY  )
    APE_CASE_RET( ETXTBSY , __WASI_ERRNO_TXTBSY )
    APE_CASE_RET( EFBIG   , __WASI_ERRNO_FBIG   )
    APE_CASE_RET( ENOSPC  , __WASI_ERRNO_NOSPC  )
    APE_CASE_RET( ESPIPE  , __WASI_ERRNO_SPIPE  )
    APE_CASE_RET( EROFS   , __WASI_ERRNO_ROFS   )
    APE_CASE_RET( EMLINK  , __WASI_ERRNO_MLINK  )
    APE_CASE_RET( EPIPE   , __WASI_ERRNO_PIPE   )
    APE_CASE_RET( EDOM    , __WASI_ERRNO_DOM    )
    APE_CASE_RET( ERANGE  , __WASI_ERRNO_RANGE  )
    APE_SWITCH_END
    return __WASI_ERRNO_INVAL;
}

#if defined(_WIN32)

#if !defined(__MINGW32__)

static inline
int clock_gettime(int clk_id, struct timespec *spec)
{
    __int64 wintime; GetSystemTimeAsFileTime((FILETIME*)&wintime);
    wintime      -= 116444736000000000i64;           //1jan1601 to 1jan1970
    spec->tv_sec  = wintime / 10000000i64;           //seconds
    spec->tv_nsec = wintime % 10000000i64 *100;      //nano-seconds
    return 0;
}

static inline
int clock_getres(int clk_id, struct timespec *spec) {
    return -1; // Defaults to 1000000
}

#endif

static inline
int convert_clockid(__wasi_clockid_t in) {
    return 0;
}

#else // _WIN32

static inline
int convert_clockid(__wasi_clockid_t in) {
    switch (in) {
    case __WASI_CLOCKID_MONOTONIC:            return CLOCK_MONOTONIC;
    case __WASI_CLOCKID_PROCESS_CPUTIME_ID:   return CLOCK_PROCESS_CPUTIME_ID;
    case __WASI_CLOCKID_REALTIME:             return CLOCK_REALTIME;
    case __WASI_CLOCKID_THREAD_CPUTIME_ID:    return CLOCK_THREAD_CPUTIME_ID;
    default: return -1;
    }
}

#endif // _WIN32

static inline
__wasi_timestamp_t convert_timespec(const struct timespec *ts) {
    if (ts->tv_sec < 0)
        return 0;
    if ((__wasi_timestamp_t)ts->tv_sec >= UINT64_MAX / 1000000000)
        return UINT64_MAX;
    return (__wasi_timestamp_t)ts->tv_sec * 1000000000 + ts->tv_nsec;
}

#if defined(HAS_IOVEC)

static inline
const void* copy_iov_to_host(IM3Runtime runtime, void* _mem, struct iovec* host_iov, wasi_iovec_t* wasi_iov, int32_t iovs_len)
{
    // Convert wasi memory offsets to host addresses
    for (int i = 0; i < iovs_len; i++) {
        host_iov[i].iov_base = m3ApiOffsetToPtr(m3ApiReadMem32(&wasi_iov[i].buf));
        host_iov[i].iov_len  = m3ApiReadMem32(&wasi_iov[i].buf_len);
        m3ApiCheckMem(host_iov[i].iov_base,     host_iov[i].iov_len);
    }
    m3ApiSuccess();
}

#endif

/*
 * WASI API implementation
 */

m3ApiRawFunction(m3_wasi_generic_args_get)
{
    m3ApiReturnType  (uint32_t)
    m3ApiGetArgMem   (uint32_t *           , argv)
    m3ApiGetArgMem   (char *               , argv_buf)

    m3_wasi_context_t* context = (m3_wasi_context_t*)(_ctx->userdata);

    if (context == NULL) { m3ApiReturn(__WASI_ERRNO_INVAL); }

    m3ApiCheckMem(argv, context->argc * sizeof(uint32_t));

    for (u32 i = 0; i < context->argc; ++i)
    {
        m3ApiWriteMem32(&argv[i], m3ApiPtrToOffset(argv_buf));

        size_t len = strlen (context->argv[i]);

        m3ApiCheckMem(argv_buf, len);
        memcpy (argv_buf, context->argv[i], len);
        argv_buf += len;
        * argv_buf++ = 0;
    }

    m3ApiReturn(__WASI_ERRNO_SUCCESS);
}

m3ApiRawFunction(m3_wasi_generic_args_sizes_get)
{
    m3ApiReturnType  (uint32_t)
    m3ApiGetArgMem   (__wasi_size_t *      , argc)
    m3ApiGetArgMem   (__wasi_size_t *      , argv_buf_size)

    m3ApiCheckMem(argc,             sizeof(__wasi_size_t));
    m3ApiCheckMem(argv_buf_size,    sizeof(__wasi_size_t));

    m3_wasi_context_t* context = (m3_wasi_context_t*)(_ctx->userdata);

    if (context == NULL) { m3ApiReturn(__WASI_ERRNO_INVAL); }

    __wasi_size_t buf_len = 0;
    for (u32 i = 0; i < context->argc; ++i)
    {
        buf_len += strlen (context->argv[i]) + 1;
    }

    m3ApiWriteMem32(argc, context->argc);
    m3ApiWriteMem32(argv_buf_size, buf_len);

    m3ApiReturn(__WASI_ERRNO_SUCCESS);
}

m3ApiRawFunction(m3_wasi_generic_environ_get)
{
    m3ApiReturnType  (uint32_t)
    m3ApiGetArgMem   (uint32_t *           , env)
    m3ApiGetArgMem   (char *               , env_buf)

    char **envp = environmentVariables(ios_currentPid());
    char **ep;
    int env_count = 0;
    int env_buf_size = 0;
    for (ep = environmentVariables(ios_currentPid()); *ep != NULL; ep++) {
        env_count ++;
        env_buf_size += strlen(*ep) + 1;
    }
    m3ApiCheckMem(env,      env_count * sizeof(uint32_t));
    m3ApiCheckMem(env_buf,  env_buf_size);

    uint32_t environ_buf_offset = m3ApiPtrToOffset(env_buf);
    int offset = environ_buf_offset;

    for (u32 i = 0; i < env_count; ++i)
    {
        strcpy(env_buf + offset - environ_buf_offset, envp[i]);
        m3ApiWriteMem32(&env[i], offset);
        offset += strlen(envp[i]) + 1;
    }

    m3ApiReturn(__WASI_ERRNO_SUCCESS);
}

m3ApiRawFunction(m3_wasi_generic_environ_sizes_get)
{
    m3ApiReturnType  (uint32_t)
    m3ApiGetArgMem   (__wasi_size_t *      , env_count)
    m3ApiGetArgMem   (__wasi_size_t *      , env_buf_size)

    m3ApiCheckMem(env_count,    sizeof(__wasi_size_t));
    m3ApiCheckMem(env_buf_size, sizeof(__wasi_size_t));

    int new_env_count = 0;
    int new_env_buf_size = 0;
    for (char **ep = environmentVariables(ios_currentPid()); *ep != NULL; ep++) {
        new_env_count ++;
        new_env_buf_size += strlen(*ep) + 1;
    }

    m3ApiWriteMem32(env_count,    new_env_count);
    m3ApiWriteMem32(env_buf_size, new_env_buf_size);

    m3ApiReturn(__WASI_ERRNO_SUCCESS);
}

m3ApiRawFunction(m3_wasi_generic_fd_prestat_dir_name)
{
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , fd)
    m3ApiGetArgMem   (char *               , path)
    m3ApiGetArg      (__wasi_size_t        , path_len)

    m3ApiCheckMem(path, path_len);

    if (fd < 3 || fd >= PREOPEN_CNT) { m3ApiReturn(__WASI_ERRNO_BADF); }
    size_t slen = strlen(preopen[fd].path) + 1;
    memcpy(path, preopen[fd].path, M3_MIN(slen, path_len));
    m3ApiReturn(__WASI_ERRNO_SUCCESS);
}

m3ApiRawFunction(m3_wasi_generic_fd_prestat_get)
{
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , fd)
    m3ApiGetArgMem   (uint8_t *            , buf)

    m3ApiCheckMem(buf, 8);

    if (fd < 3 || fd >= PREOPEN_CNT) { m3ApiReturn(__WASI_ERRNO_BADF); }

    m3ApiWriteMem32(buf+0, __WASI_PREOPENTYPE_DIR);
    m3ApiWriteMem32(buf+4, strlen(preopen[fd].path) + 1);
    m3ApiReturn(__WASI_ERRNO_SUCCESS);
}

m3ApiRawFunction(m3_wasi_generic_fd_fdstat_get)
{
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , fd)
    m3ApiGetArgMem   (__wasi_fdstat_t *    , fdstat)

    m3ApiCheckMem(fdstat, sizeof(__wasi_fdstat_t));

#ifdef _WIN32

    // TODO: This needs a proper implementation
    if (fd < PREOPEN_CNT) {
        fdstat->fs_filetype= __WASI_FILETYPE_DIRECTORY;
    } else {
        fdstat->fs_filetype= __WASI_FILETYPE_REGULAR_FILE;
    }

    fdstat->fs_flags = 0;
    fdstat->fs_rights_base = (uint64_t)-1; // all rights
    fdstat->fs_rights_inheriting = (uint64_t)-1; // all rights
    m3ApiReturn(__WASI_ERRNO_SUCCESS);
#else
    struct stat fd_stat;

#if TARGET_OS_IPHONE
    // Make descriptors 0,1,2 look like a TTY
    // TODO: check whether it's actually the TTY, nor something redirected.
    // And HOW? xz -dcf < testFile.xz > outputFile
    if (ios_isatty(fd)) {
        fdstat->fs_filetype = __WASI_FILETYPE_CHARACTER_DEVICE;
        fdstat->fs_rights_base = (uint64_t)-1; // all rights
        fdstat->fs_rights_base &= ~(__WASI_RIGHTS_FD_SEEK | __WASI_RIGHTS_FD_TELL);
        fdstat->fs_rights_inheriting = (uint64_t)-1; // all rights
        m3ApiReturn(__WASI_ERRNO_SUCCESS);
    }
    // iOS, not a TTY:
    if (fd == STDIN_FILENO)
        fd = fileno(thread_stdin);
    else if (fd == STDOUT_FILENO)
        fd = fileno(thread_stdout);
    else if (fd == STDERR_FILENO)
        fd = fileno(thread_stderr);
#endif
    
#if !defined(APE) // TODO: not implemented in Cosmopolitan
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0) { m3ApiReturn(errno_to_wasi(errno)); }
#endif

    fstat(fd, &fd_stat);
    int mode = fd_stat.st_mode;
    fdstat->fs_filetype = (S_ISBLK(mode)   ? __WASI_FILETYPE_BLOCK_DEVICE     : 0) |
                          (S_ISCHR(mode)   ? __WASI_FILETYPE_CHARACTER_DEVICE : 0) |
                          (S_ISDIR(mode)   ? __WASI_FILETYPE_DIRECTORY        : 0) |
                          (S_ISREG(mode)   ? __WASI_FILETYPE_REGULAR_FILE     : 0) |
                          //(S_ISSOCK(mode)  ? __WASI_FILETYPE_SOCKET_STREAM    : 0) |
                          (S_ISLNK(mode)   ? __WASI_FILETYPE_SYMBOLIC_LINK    : 0);
#if !defined(APE)
    m3ApiWriteMem16(&fdstat->fs_flags,
                       ((fl & O_APPEND)    ? __WASI_FDFLAGS_APPEND    : 0) |
                       ((fl & O_DSYNC)     ? __WASI_FDFLAGS_DSYNC     : 0) |
                       ((fl & O_NONBLOCK)  ? __WASI_FDFLAGS_NONBLOCK  : 0) |
                       //((fl & O_RSYNC)     ? __WASI_FDFLAGS_RSYNC     : 0) |
                       ((fl & O_SYNC)      ? __WASI_FDFLAGS_SYNC      : 0));
#endif // APE

    fdstat->fs_rights_base = (uint64_t)-1; // all rights

    // Make descriptors 0,1,2 look like a TTY
#if !TARGET_OS_IPHONE
    if (fd <= 2) {
        fdstat->fs_rights_base &= ~(__WASI_RIGHTS_FD_SEEK | __WASI_RIGHTS_FD_TELL);
    }
#endif
    fdstat->fs_rights_inheriting = (uint64_t)-1; // all rights
    m3ApiReturn(__WASI_ERRNO_SUCCESS);
#endif
}

m3ApiRawFunction(m3_wasi_generic_fd_fdstat_set_flags)
{
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , fd)
    m3ApiGetArg      (__wasi_fdflags_t     , flags)

    // a-Shell specific implementation:
#if TARGET_OS_IPHONE
    __wasi_fd_t fd_orig = fd;
    if (fd == STDIN_FILENO)
        fd = fileno(thread_stdin);
    else if (fd == STDOUT_FILENO)
        fd = fileno(thread_stdout);
    else if (fd == STDERR_FILENO)
        fd = fileno(thread_stderr);
#endif
    if (fcntl(fd, F_SETFL, flags) == 0)
        m3ApiReturn(__WASI_ERRNO_SUCCESS);
    m3ApiReturn(errno_to_wasi(errno));
}

m3ApiRawFunction(m3_wasi_generic_fd_filestat_set_size)
{
    // a-Shell addition
    // i(iI)
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , fd)
    m3ApiGetArg      (__wasi_filesize_t    , size)

    // a-Shell specific implementation:
#if TARGET_OS_IPHONE
    __wasi_fd_t fd_orig = fd;
    if (fd == STDIN_FILENO)
        fd = fileno(thread_stdin);
    else if (fd == STDOUT_FILENO)
        fd = fileno(thread_stdout);
    else if (fd == STDERR_FILENO)
        fd = fileno(thread_stderr);
#endif
    if (ftruncate(fd, size) == 0)
        m3ApiReturn(__WASI_ERRNO_SUCCESS);
    m3ApiReturn(errno_to_wasi(errno));
}

m3ApiRawFunction(m3_wasi_unstable_fd_seek)
{
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , fd)
    m3ApiGetArg      (__wasi_filedelta_t   , offset)
    m3ApiGetArg      (uint32_t             , wasi_whence)
    m3ApiGetArgMem   (__wasi_filesize_t *  , result)

    m3ApiCheckMem(result, sizeof(__wasi_filesize_t));
#if TARGET_OS_IPHONE
    __wasi_fd_t fd_orig = fd;
    if (fd == STDIN_FILENO)
        fd = fileno(thread_stdin);
    else if (fd == STDOUT_FILENO)
        fd = fileno(thread_stdout);
    else if (fd == STDERR_FILENO)
        fd = fileno(thread_stderr);
#endif

    int whence;

    switch (wasi_whence) {
    case 0: whence = SEEK_CUR; break;
    case 1: whence = SEEK_END; break;
    case 2: whence = SEEK_SET; break;
    default:                m3ApiReturn(__WASI_ERRNO_INVAL);
    }

    int64_t ret;
#if defined(M3_COMPILER_MSVC) || defined(__MINGW32__)
    ret = _lseeki64(fd, offset, whence);
#else
    ret = lseek(fd, offset, whence);
#endif
    if (ret < 0) { m3ApiReturn(errno_to_wasi(errno)); }
    m3ApiWriteMem64(result, ret);
    m3ApiReturn(__WASI_ERRNO_SUCCESS);
}

m3ApiRawFunction(m3_wasi_snapshot_preview1_fd_seek)
{
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , fd)
    m3ApiGetArg      (__wasi_filedelta_t   , offset)
    m3ApiGetArg      (uint32_t             , wasi_whence)
    m3ApiGetArgMem   (__wasi_filesize_t *  , result)

    m3ApiCheckMem(result, sizeof(__wasi_filesize_t));
#if TARGET_OS_IPHONE
    __wasi_fd_t fd_orig = fd;
    if (fd == STDIN_FILENO)
        fd = fileno(thread_stdin);
    else if (fd == STDOUT_FILENO)
        fd = fileno(thread_stdout);
    else if (fd == STDERR_FILENO)
        fd = fileno(thread_stderr);
#endif

    int whence;

    switch (wasi_whence) {
    case 0: whence = SEEK_SET; break;
    case 1: whence = SEEK_CUR; break;
    case 2: whence = SEEK_END; break;
    default:                m3ApiReturn(__WASI_ERRNO_INVAL);
    }

    int64_t ret;
#if defined(M3_COMPILER_MSVC) || defined(__MINGW32__)
    ret = _lseeki64(fd, offset, whence);
#else
    ret = lseek(fd, offset, whence);
#endif
    if (ret < 0) { m3ApiReturn(errno_to_wasi(errno)); }
    m3ApiWriteMem64(result, ret);
    m3ApiReturn(__WASI_ERRNO_SUCCESS);
}


m3ApiRawFunction(m3_wasi_generic_path_open)
{
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , dirfd)
    m3ApiGetArg      (__wasi_lookupflags_t , dirflags)
    m3ApiGetArgMem   (const char *         , path)
    m3ApiGetArg      (__wasi_size_t        , path_len)
    m3ApiGetArg      (__wasi_oflags_t      , oflags)
    m3ApiGetArg      (__wasi_rights_t      , fs_rights_base)
    m3ApiGetArg      (__wasi_rights_t      , fs_rights_inheriting)
    m3ApiGetArg      (__wasi_fdflags_t     , fs_flags)
    m3ApiGetArgMem   (__wasi_fd_t *        , fd)

    m3ApiCheckMem(path, path_len);
    m3ApiCheckMem(fd,   sizeof(__wasi_fd_t));

    if (path_len >= 512)
        m3ApiReturn(__WASI_ERRNO_INVAL);

    // copy path so we can ensure it is NULL terminated
#if defined(M3_COMPILER_MSVC)
    char host_path[512];
#else
    char host_path[path_len+1];
#endif
    memcpy (host_path, path, path_len);
    host_path[path_len] = '\0'; // NULL terminator

#if defined(APE)
    // TODO: This all needs a proper implementation

    int flags = ((oflags & __WASI_OFLAGS_CREAT)             ? O_CREAT     : 0) |
                ((oflags & __WASI_OFLAGS_EXCL)              ? O_EXCL      : 0) |
                ((oflags & __WASI_OFLAGS_TRUNC)             ? O_TRUNC     : 0) |
                ((fs_flags & __WASI_FDFLAGS_APPEND)     ? O_APPEND    : 0);

    if ((fs_rights_base & __WASI_RIGHTS_FD_READ) &&
        (fs_rights_base & __WASI_RIGHTS_FD_WRITE)) {
        flags |= O_RDWR;
    } else if ((fs_rights_base & __WASI_RIGHTS_FD_WRITE)) {
        flags |= O_WRONLY;
    } else if ((fs_rights_base & __WASI_RIGHTS_FD_READ)) {
        flags |= O_RDONLY; // no-op because O_RDONLY is 0
    }
    int mode = 0644;

    int host_fd = open (host_path, flags, mode);

    if (host_fd < 0)
    {
        m3ApiReturn(errno_to_wasi (errno));
    }
    else
    {
        m3ApiWriteMem32(fd, host_fd);
        m3ApiReturn(__WASI_ERRNO_SUCCESS);
    }
#elif defined(_WIN32)
    // TODO: This all needs a proper implementation

    int flags = ((oflags & __WASI_OFLAGS_CREAT)             ? _O_CREAT     : 0) |
                ((oflags & __WASI_OFLAGS_EXCL)              ? _O_EXCL      : 0) |
                ((oflags & __WASI_OFLAGS_TRUNC)             ? _O_TRUNC     : 0) |
                ((fs_flags & __WASI_FDFLAGS_APPEND)         ? _O_APPEND    : 0) |
                _O_BINARY;

    if ((fs_rights_base & __WASI_RIGHTS_FD_READ) &&
        (fs_rights_base & __WASI_RIGHTS_FD_WRITE)) {
        flags |= _O_RDWR;
    } else if ((fs_rights_base & __WASI_RIGHTS_FD_WRITE)) {
        flags |= _O_WRONLY;
    } else if ((fs_rights_base & __WASI_RIGHTS_FD_READ)) {
        flags |= _O_RDONLY; // no-op because O_RDONLY is 0
    }
    int mode = 0644;

    int host_fd = open (host_path, flags, mode);

    if (host_fd < 0)
    {
        m3ApiReturn(errno_to_wasi (errno));
    }
    else
    {
        m3ApiWriteMem32(fd, host_fd);
        m3ApiReturn(__WASI_ERRNO_SUCCESS);
    }
#else
    // translate o_flags and fs_flags into flags and mode
    int flags = ((oflags & __WASI_OFLAGS_CREAT)             ? O_CREAT     : 0) |
                //((oflags & __WASI_OFLAGS_DIRECTORY)         ? O_DIRECTORY : 0) |
                ((oflags & __WASI_OFLAGS_EXCL)              ? O_EXCL      : 0) |
                ((oflags & __WASI_OFLAGS_TRUNC)             ? O_TRUNC     : 0) |
                ((fs_flags & __WASI_FDFLAGS_APPEND)     ? O_APPEND    : 0) |
                ((fs_flags & __WASI_FDFLAGS_DSYNC)      ? O_DSYNC     : 0) |
                ((fs_flags & __WASI_FDFLAGS_NONBLOCK)   ? O_NONBLOCK  : 0) |
                //((fs_flags & __WASI_FDFLAGS_RSYNC)      ? O_RSYNC     : 0) |
                ((fs_flags & __WASI_FDFLAGS_SYNC)       ? O_SYNC      : 0);
    if ((fs_rights_base & __WASI_RIGHTS_FD_READ) &&
        (fs_rights_base & __WASI_RIGHTS_FD_WRITE)) {
        flags |= O_RDWR;
    } else if ((fs_rights_base & __WASI_RIGHTS_FD_WRITE)) {
        flags |= O_WRONLY;
    } else if ((fs_rights_base & __WASI_RIGHTS_FD_READ)) {
        flags |= O_RDONLY; // no-op because O_RDONLY is 0
    }
    int mode = 0644;
    
#if TARGET_OS_IPHONE
    int host_fd = open(host_path, flags, mode);
#else
    int host_fd = openat (preopen[dirfd].fd, host_path, flags, mode);
#endif

    if (host_fd < 0)
    {
        m3ApiReturn(errno_to_wasi (errno));
    }
    else
    {
        m3ApiWriteMem32(fd, host_fd);
        m3ApiReturn(__WASI_ERRNO_SUCCESS);
    }
#endif
}

m3ApiRawFunction(m3_wasi_generic_fd_read)
{
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , fd)
    m3ApiGetArgMem   (wasi_iovec_t *       , wasi_iovs)
    m3ApiGetArg      (__wasi_size_t        , iovs_len)
    m3ApiGetArgMem   (__wasi_size_t *      , nread)

    m3ApiCheckMem(wasi_iovs,    iovs_len * sizeof(wasi_iovec_t));
    m3ApiCheckMem(nread,        sizeof(__wasi_size_t));

#if TARGET_OS_IPHONE
    __wasi_fd_t fd_orig = fd;
    if (fd == STDIN_FILENO)
        fd = fileno(thread_stdin);
    else if (fd == STDOUT_FILENO)
        fd = fileno(thread_stdout);
    else if (fd == STDERR_FILENO)
        fd = fileno(thread_stderr);
#endif

#if defined(HAS_IOVEC)
    struct iovec iovs[iovs_len];
    const void* mem_check = copy_iov_to_host(runtime, _mem, iovs, wasi_iovs, iovs_len);
    if (mem_check != m3Err_none) {
        return mem_check;
    }

    ssize_t ret = readv(fd, iovs, iovs_len);
    if (ret < 0) { m3ApiReturn(errno_to_wasi(errno)); }
    m3ApiWriteMem32(nread, ret);
    m3ApiReturn(__WASI_ERRNO_SUCCESS);
#else
    ssize_t res = 0;
    for (__wasi_size_t i = 0; i < iovs_len; i++) {
        void* addr = m3ApiOffsetToPtr(m3ApiReadMem32(&wasi_iovs[i].buf));
        size_t len = m3ApiReadMem32(&wasi_iovs[i].buf_len);
        if (len == 0) continue;
        m3ApiCheckMem(addr,     len);
        int ret = read (fd, addr, len);
        if (ret < 0) m3ApiReturn(errno_to_wasi(errno));
        res += ret;
        if ((size_t)ret < len) break;
    }
    m3ApiWriteMem32(nread, res);
    m3ApiReturn(__WASI_ERRNO_SUCCESS);
#endif
}

m3ApiRawFunction(m3_wasi_generic_fd_pread)
{
    // i(i*iI*)
    // fd, iovs, iovsLen, offset, nread
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , fd)
    m3ApiGetArgMem   (wasi_iovec_t *       , wasi_iovs)
    m3ApiGetArg      (__wasi_size_t        , iovs_len)
    m3ApiGetArg      (__wasi_filesize_t    , offset)
    m3ApiGetArgMem   (__wasi_size_t *      , nread)

    m3ApiCheckMem(wasi_iovs,    iovs_len * sizeof(wasi_iovec_t));
    m3ApiCheckMem(nread,        sizeof(__wasi_size_t));

#if TARGET_OS_IPHONE
    __wasi_fd_t fd_orig = fd;
    if (fd == STDIN_FILENO)
        fd = fileno(thread_stdin);
    else if (fd == STDOUT_FILENO)
        fd = fileno(thread_stdout);
    else if (fd == STDERR_FILENO)
        fd = fileno(thread_stderr);
#endif

    struct iovec iovs[iovs_len];
    const void* mem_check = copy_iov_to_host(runtime, _mem, iovs, wasi_iovs, iovs_len);
    if (mem_check != m3Err_none) {
        return mem_check;
    }

    ssize_t ret = preadv(fd, iovs, iovs_len, offset);
    if (ret < 0) { m3ApiReturn(errno_to_wasi(errno)); }
    m3ApiWriteMem32(nread, ret);
    m3ApiReturn(__WASI_ERRNO_SUCCESS);
}

m3ApiRawFunction(m3_wasi_generic_fd_write)
{
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , fd)
    m3ApiGetArgMem   (wasi_iovec_t *       , wasi_iovs)
    m3ApiGetArg      (__wasi_size_t        , iovs_len)
    m3ApiGetArgMem   (__wasi_size_t *      , nwritten)

    m3ApiCheckMem(wasi_iovs,    iovs_len * sizeof(wasi_iovec_t));
    m3ApiCheckMem(nwritten,     sizeof(__wasi_size_t));

#if defined(HAS_IOVEC)
    struct iovec iovs[iovs_len];
    const void* mem_check = copy_iov_to_host(runtime, _mem, iovs, wasi_iovs, iovs_len);
    if (mem_check != m3Err_none) {
        return mem_check;
    }

#if TARGET_OS_IPHONE
    if (fd == STDOUT_FILENO)
        fd = fileno(thread_stdout);
    else if (fd == STDERR_FILENO)
        fd = fileno(thread_stderr);
#endif
    ssize_t ret = writev(fd, iovs, iovs_len);
    
    if (ret < 0) { m3ApiReturn(errno_to_wasi(errno)); }
    m3ApiWriteMem32(nwritten, ret);
    m3ApiReturn(__WASI_ERRNO_SUCCESS);
#else
    ssize_t res = 0;
    for (__wasi_size_t i = 0; i < iovs_len; i++) {
        void* addr = m3ApiOffsetToPtr(m3ApiReadMem32(&wasi_iovs[i].buf));
        size_t len = m3ApiReadMem32(&wasi_iovs[i].buf_len);
        if (len == 0) continue;
        m3ApiCheckMem(addr,     len);
        int ret = write (fd, addr, len);
        if (ret < 0) m3ApiReturn(errno_to_wasi(errno));
        res += ret;
        if ((size_t)ret < len) break;
    }
    m3ApiWriteMem32(nwritten, res);
    m3ApiReturn(__WASI_ERRNO_SUCCESS);
#endif
}

m3ApiRawFunction(m3_wasi_generic_fd_pwrite)
{
    // a-Shell specific function
    // i(i*iI*)
    // fd, iovs, iovsLen, offset, nwritten
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , fd)
    m3ApiGetArgMem   (wasi_iovec_t *       , wasi_iovs)
    m3ApiGetArg      (__wasi_size_t        , iovs_len)
    m3ApiGetArg      (__wasi_filesize_t    , offset)
    m3ApiGetArgMem   (__wasi_size_t *      , nwritten)

    m3ApiCheckMem(wasi_iovs,    iovs_len * sizeof(wasi_iovec_t));
    m3ApiCheckMem(nwritten,     sizeof(__wasi_size_t));

    struct iovec iovs[iovs_len];
    const void* mem_check = copy_iov_to_host(runtime, _mem, iovs, wasi_iovs, iovs_len);
    if (mem_check != m3Err_none) {
        return mem_check;
    }

#if TARGET_OS_IPHONE
    if (fd == STDOUT_FILENO)
        fd = fileno(thread_stdout);
    else if (fd == STDERR_FILENO)
        fd = fileno(thread_stderr);
#endif
    ssize_t ret = pwritev(fd, iovs, iovs_len, offset);
    
    if (ret < 0) { m3ApiReturn(errno_to_wasi(errno)); }
    m3ApiWriteMem32(nwritten, ret);
    m3ApiReturn(__WASI_ERRNO_SUCCESS);
}

m3ApiRawFunction(m3_wasi_generic_fd_close)
{
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t, fd)

#if TARGET_OS_IPHONE
    __wasi_fd_t fd_orig = fd;
    if (fd == STDIN_FILENO)
        fd = fileno(thread_stdin);
    else if (fd == STDOUT_FILENO)
        fd = fileno(thread_stdout);
    else if (fd == STDERR_FILENO)
        fd = fileno(thread_stderr);
#endif

    if (fd_orig < 3)
        m3ApiReturn(__WASI_ERRNO_SUCCESS);
    int ret = close(fd);
    m3ApiReturn(ret == 0 ? __WASI_ERRNO_SUCCESS : ret);
}

m3ApiRawFunction(m3_wasi_generic_fd_datasync)
{
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t, fd)

#if TARGET_OS_IPHONE
    __wasi_fd_t fd_orig = fd;
    if (fd == STDIN_FILENO)
        fd = fileno(thread_stdin);
    else if (fd == STDOUT_FILENO)
        fd = fileno(thread_stdout);
    else if (fd == STDERR_FILENO)
        fd = fileno(thread_stderr);
#endif

#if defined(_WIN32)
    int ret = _commit(fd);
#elif defined(__APPLE__)
    int ret = fsync(fd);
#elif defined(__ANDROID_API__) || defined(__OpenBSD__) || defined(__linux__) || defined(__EMSCRIPTEN__)
    int ret = fdatasync(fd);
#else
    int ret = __WASI_ERRNO_NOSYS;
#endif
    m3ApiReturn(ret == 0 ? __WASI_ERRNO_SUCCESS : ret);
}

// rust programs (ripgrep) can call readdir() on sub-directories while scanning a directory.
// So we store dir_entry and file_entry for each file descriptor. There are only 1280 of them.
DIR* dir_entry[1280];
struct dirent* file_entry[1280];

m3ApiRawFunction(m3_wasi_generic_fd_readdir)
{
    // i(i*iI*)
    // fd, bufPtr, bufLen, cookie, bufusedPtr
    // __wasi_fd_t fd,
    // The buffer where directory entries are stored
    // uint8_t * buf,
    // __wasi_size_t buf_len,
    // The location within the directory to start reading
    // __wasi_dircookie_t cookie,
    // __wasi_size_t *retptr0

    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , fd)
    m3ApiGetArgMem   (uint8_t *            , buf)
    m3ApiGetArg      (__wasi_size_t        , buf_len)
    m3ApiGetArg      (__wasi_dircookie_t   , cookie)
    m3ApiGetArgMem   (__wasi_size_t *      , retptr0)

    m3ApiCheckMem(buf,        sizeof(buf_len));

    if (cookie == __WASI_DIRCOOKIE_START)  {
        dir_entry[fd] = fdopendir(fd);
        file_entry[fd] = NULL;
        if (dir_entry[fd] == NULL)
            m3ApiReturn(__WASI_ERRNO_PERM);
    }
    fflush(stderr);
    int offset = 0;
    if (dir_entry[fd] == NULL) {
        // directory already closed.
        m3ApiWriteMem64(retptr0, offset);
        m3ApiReturn(__WASI_ERRNO_SUCCESS);
    }
    if (file_entry[fd] == NULL) {
        file_entry[fd] = readdir(dir_entry[fd]);
    }
    while (file_entry[fd] != NULL) {
        // store file_entry + name into buf:
        __wasi_dirent_t entry;
        entry.d_namlen = file_entry[fd]->d_namlen;
        entry.d_ino = file_entry[fd]->d_ino;
        entry.d_type = file_entry[fd]->d_type;
        entry.d_type =  ((file_entry[fd]->d_type == DT_REG) ? __WASI_FILETYPE_REGULAR_FILE     : 0) |
                        ((file_entry[fd]->d_type == DT_DIR) ? __WASI_FILETYPE_DIRECTORY     : 0) |
                        ((file_entry[fd]->d_type == DT_BLK) ? __WASI_FILETYPE_BLOCK_DEVICE     : 0) |
                        ((file_entry[fd]->d_type == DT_CHR) ? __WASI_FILETYPE_CHARACTER_DEVICE     : 0) |
                        ((file_entry[fd]->d_type == DT_LNK) ? __WASI_FILETYPE_SYMBOLIC_LINK     : 0);
        entry.d_next = 1;
        if (offset + sizeof(__wasi_dirent_t) > buf_len) {
            offset = buf_len;
            break;
        }
        memcpy (buf + offset, &entry, sizeof(__wasi_dirent_t));
        if (offset + sizeof(__wasi_dirent_t) + file_entry[fd]->d_namlen > buf_len) {
            offset = buf_len;
            break;
        }
        // buffer is very small. 128 bytes. Why?
        memcpy (buf + offset + sizeof(__wasi_dirent_t), file_entry[fd]->d_name, file_entry[fd]->d_namlen);
        offset += sizeof(__wasi_dirent_t) + file_entry[fd]->d_namlen;
        fflush(stderr);
        file_entry[fd] = readdir(dir_entry[fd]);
    }
    if (file_entry[fd] == NULL) {
        closedir(dir_entry[fd]);
        dir_entry[fd] = NULL;
        file_entry[fd] = NULL;
        fflush(stderr);
    }
    // store number of bytes in retptr0:
    m3ApiWriteMem64(retptr0, offset);
    m3ApiReturn(__WASI_ERRNO_SUCCESS);
}

m3ApiRawFunction(m3_wasi_generic_fd_tell)
{
    // i(i*)
    // fd, result
    // __wasi_fd_t fd,
    // __wasi_filesize_t *retptr0

    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , fd)
    m3ApiGetArgMem   (__wasi_filesize_t *      , retptr0)

    // Need to map fd to actual path for ftell
    off_t returnValue = lseek(fd, 0, SEEK_CUR);
    if (returnValue >= 0) {
        m3ApiWriteMem64(retptr0, returnValue);
        m3ApiReturn(__WASI_ERRNO_SUCCESS);
    }
    m3ApiReturn(errno_to_wasi(errno));
}

m3ApiRawFunction(m3_wasi_generic_fd_sync)
{
    // i(i)
    // __wasi_fd_t fd,

    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , fd)

    if (fsync(fd) == 0) {
        m3ApiReturn(__WASI_ERRNO_SUCCESS);
    }
    m3ApiReturn(errno_to_wasi(errno));
}

m3ApiRawFunction(m3_wasi_generic_path_create_directory)
{
    // i(i*i)
    m3ApiReturnType  (uint32_t)
    m3ApiGetArgMem   (char *               , path)
    m3ApiGetArg      (__wasi_size_t        , path_len)

    m3ApiCheckMem(path, path_len);

    if (mkdir(path, S_IRWXU|S_IRWXG|S_IRWXO) == 0)
        m3ApiReturn(__WASI_ERRNO_SUCCESS);
    m3ApiReturn(errno_to_wasi(errno));
}

m3ApiRawFunction(m3_wasi_generic_path_filestat_set_times)
{
    // i(ii*iIIi)
    // fd, fstflags, pathPtr, pathLen, stAtim, stAtim_ns, stMtim, stMtim_ns, lookupflags
    // __wasi_fd_t fd,
    // Flags determining the method of how the path is resolved.
    // __wasi_lookupflags_t flags,
    // The path of the file or directory to operate on.
    // const char *path,
    // The desired values of the data access timestamp (seconds).
    // __wasi_timestamp_t atim,
    // desired values of the data access timestamp (nanoseconds).
    // __wasi_timestamp_t atim_ns,
    // The desired values of the data modification timestamp (seconds).
    // __wasi_timestamp_t mtim,
    // desired values of the data modification timestamp (nanoseconds).
    // __wasi_timestamp_t mtim_ns,
    // A bitmask indicating which timestamps to adjust.
    // __wasi_fstflags_t fst_flags

    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , fd)
    m3ApiGetArg      (__wasi_lookupflags_t , flags)
    m3ApiGetArgMem   (char *               , path)
    m3ApiGetArg      (__wasi_size_t        , path_len)
    m3ApiGetArg      (__wasi_timestamp_t   , atim)
    // m3ApiGetArg      (__wasi_timestamp_t   , atim_ns)
     m3ApiGetArg      (__wasi_timestamp_t   , mtim)
//     m3ApiGetArg      (__wasi_timestamp_t   , mtim_ns)
    m3ApiGetArg      (__wasi_fstflags_t    , fst_flags)

    m3ApiCheckMem(path, path_len);

    // Make the time:
    struct timespec time[2];
    if (fst_flags & __WASI_FSTFLAGS_ATIM_NOW) {
        clock_gettime(CLOCK_REALTIME, &time[0]);
    } else {
        time[0].tv_nsec = atim % 1000000000;
        time[0].tv_sec = atim / 1000000000;
    }
    if (fst_flags & __WASI_FSTFLAGS_MTIM_NOW) {
        clock_gettime(CLOCK_REALTIME, &time[1]);
    } else {
        time[1].tv_nsec = mtim % 1000000000;
        time[1].tv_sec = mtim / 1000000000;
    }

    int myFlags = 0;
    if ((flags & __WASI_LOOKUPFLAGS_SYMLINK_FOLLOW) == 0) myFlags |= AT_SYMLINK_NOFOLLOW;
    
    if (utimensat(fd, path, time, myFlags) == 0)
        m3ApiReturn(__WASI_ERRNO_SUCCESS);
    m3ApiReturn(errno_to_wasi(errno));
}

m3ApiRawFunction(m3_wasi_generic_path_link)
{
    // i(ii*ii*i)
    // oldFd, oldFlags, oldPath, oldPathLen, newFd, newPath, newPathLen
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , oldFd)
    m3ApiGetArg      (__wasi_lookupflags_t , oldFlags)
    m3ApiGetArgMem   (char *               , oldPath)
    m3ApiGetArg      (__wasi_size_t        , oldPath_len)
    m3ApiGetArg      (__wasi_fd_t          , newFd)
    m3ApiGetArgMem   (char *               , newPath)
    m3ApiGetArg      (__wasi_size_t        , newPath_len)

    m3ApiCheckMem(oldPath, oldPath_len);
    m3ApiCheckMem(newPath, newPath_len);

    if (linkat(oldFd, oldPath, newFd, newPath, oldFlags) == 0)
        m3ApiReturn(__WASI_ERRNO_SUCCESS);
    m3ApiReturn(errno_to_wasi(errno));
}

m3ApiRawFunction(m3_wasi_generic_path_readlink)
{
    // i(i*i*i*)
    // fd, pathPtr, pathLen, buf, bufLen, bufused
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , fd)
    m3ApiGetArgMem   (char *               , path)
    m3ApiGetArg      (__wasi_size_t        , path_len)
    m3ApiGetArgMem   (char *               , buf)
    m3ApiGetArg      (__wasi_size_t        , buf_len)
    m3ApiGetArgMem   (__wasi_size_t *      , retptr0)

    m3ApiCheckMem(path, path_len);
    m3ApiCheckMem(buf, buf_len);

    ssize_t returnValue = readlink(path, buf, buf_len);
    if (returnValue >= 0) {
        m3ApiWriteMem64(retptr0, returnValue);
        m3ApiReturn(__WASI_ERRNO_SUCCESS);
    }
    m3ApiReturn(errno_to_wasi(errno));
}

m3ApiRawFunction(m3_wasi_generic_path_symlink)
{
    // i(*ii*i)
    // oldPath, oldPathLen, fd, newPath, newPathLen
    m3ApiReturnType  (uint32_t)
    m3ApiGetArgMem   (char *               , oldPath)
    m3ApiGetArg      (__wasi_size_t        , oldPath_len)
    m3ApiGetArg      (__wasi_fd_t          , fd)
    m3ApiGetArgMem   (char *               , newPath)
    m3ApiGetArg      (__wasi_size_t        , newPath_len)

    m3ApiCheckMem(oldPath, oldPath_len);
    m3ApiCheckMem(newPath, newPath_len);

    if (symlinkat(oldPath, fd, newPath) == 0) {
        m3ApiReturn(__WASI_ERRNO_SUCCESS);
    }
    m3ApiReturn(errno_to_wasi(errno));
}

m3ApiRawFunction(m3_wasi_generic_path_rename)
{
    // i(i*ii*i)
    // oldFd, oldPath, oldPathLen, newFd, newPath, newPathLen
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , oldFd)
    m3ApiGetArgMem   (char *               , oldPath)
    m3ApiGetArg      (__wasi_size_t        , oldPath_len)
    m3ApiGetArg      (__wasi_fd_t          , newFd)
    m3ApiGetArgMem   (char *               , newPath)
    m3ApiGetArg      (__wasi_size_t        , newPath_len)

    m3ApiCheckMem(oldPath, oldPath_len);
    m3ApiCheckMem(newPath, newPath_len);

    if (renameat(oldFd, oldPath, newFd, newPath) == 0) {
        m3ApiReturn(__WASI_ERRNO_SUCCESS);
    }
    m3ApiReturn(errno_to_wasi(errno));
}

m3ApiRawFunction(m3_wasi_generic_path_remove_directory)
{
    // i(i*i)
    // fd, pathPtr, pathLen
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , fd)
    m3ApiGetArgMem   (char *               , path)
    m3ApiGetArg      (__wasi_size_t        , path_len)

    m3ApiCheckMem(path, path_len);

    if (rmdir(path) == 0) {
        m3ApiReturn(__WASI_ERRNO_SUCCESS);
    }
    m3ApiReturn(errno_to_wasi(errno));
}


m3ApiRawFunction(m3_wasi_generic_random_get)
{
    m3ApiReturnType  (uint32_t)
    m3ApiGetArgMem   (uint8_t *            , buf)
    m3ApiGetArg      (__wasi_size_t        , buf_len)

    m3ApiCheckMem(buf, buf_len);

    while (1) {
        ssize_t retlen = 0;

#if defined(__wasi__) || defined(__APPLE__) || defined(__ANDROID_API__) || defined(__OpenBSD__) || defined(__EMSCRIPTEN__)
        size_t reqlen = M3_MIN (buf_len, 256);
#   if defined(__APPLE__) && (TARGET_OS_IPHONE || TARGET_IPHONE_SIMULATOR)
        retlen = SecRandomCopyBytes(kSecRandomDefault, reqlen, buf) < 0 ? -1 : reqlen;
#   else
        retlen = getentropy(buf, reqlen) < 0 ? -1 : reqlen;
#   endif
#elif defined(__FreeBSD__) || defined(__linux__)
        retlen = getrandom(buf, buf_len, 0);
#elif defined(_WIN32)
        if (RtlGenRandom(buf, buf_len) == TRUE) {
            m3ApiReturn(__WASI_ERRNO_SUCCESS);
        }
#else
        m3ApiReturn(__WASI_ERRNO_NOSYS);
#endif
        if (retlen < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            m3ApiReturn(errno_to_wasi(errno));
        } else if (retlen == buf_len) {
            m3ApiReturn(__WASI_ERRNO_SUCCESS);
        } else {
            buf     += retlen;
            buf_len -= retlen;
        }
    }
}

m3ApiRawFunction(m3_wasi_generic_clock_res_get)
{
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_clockid_t     , wasi_clk_id)
    m3ApiGetArgMem   (__wasi_timestamp_t * , resolution)

    m3ApiCheckMem(resolution, sizeof(__wasi_timestamp_t));

    int clk = convert_clockid(wasi_clk_id);
    if (clk < 0) m3ApiReturn(__WASI_ERRNO_INVAL);

    struct timespec tp;
    if (clock_getres(clk, &tp) != 0) {
        m3ApiWriteMem64(resolution, 1000000);
    } else {
        m3ApiWriteMem64(resolution, convert_timespec(&tp));
    }

    m3ApiReturn(__WASI_ERRNO_SUCCESS);
}

m3ApiRawFunction(m3_wasi_generic_clock_time_get)
{
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_clockid_t     , wasi_clk_id)
    m3ApiGetArg      (__wasi_timestamp_t   , precision)
    m3ApiGetArgMem   (__wasi_timestamp_t * , time)

    m3ApiCheckMem(time, sizeof(__wasi_timestamp_t));

    int clk = convert_clockid(wasi_clk_id);
    if (clk < 0) m3ApiReturn(__WASI_ERRNO_INVAL);

    struct timespec tp;
    if (clock_gettime(clk, &tp) != 0) {
        m3ApiReturn(errno_to_wasi(errno));
    }

    m3ApiWriteMem64(time, convert_timespec(&tp));
    m3ApiReturn(__WASI_ERRNO_SUCCESS);
}

m3ApiRawFunction(m3_wasi_generic_proc_exit)
{
    m3ApiGetArg      (uint32_t, code)

    m3_wasi_context_t* context = (m3_wasi_context_t*)(_ctx->userdata);

    if (context) {
        context->exit_code = code;
    }

    m3ApiTrap(m3Err_trapExit);
}

// a-Shell additions:
m3ApiRawFunction(m3_wasi_snapshot_preview1_fd_filestat_get)
{
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , fd)
    m3ApiGetArgMem   (__wasi_filestat_t *    , filestat)

    m3ApiCheckMem(filestat, sizeof(__wasi_filestat_t));
    
    struct stat fd_stat;

#if TARGET_OS_IPHONE
    __wasi_fd_t fd_orig = fd;
    if (fd == STDIN_FILENO)
        fd = fileno(thread_stdin);
    else if (fd == STDOUT_FILENO)
        fd = fileno(thread_stdout);
    else if (fd == STDERR_FILENO)
        fd = fileno(thread_stderr);
#endif
    
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0) { m3ApiReturn(errno_to_wasi(errno)); }
    int returnValue = fstat(fd, &fd_stat);
    
    if (returnValue < 0) {
        m3ApiReturn(errno_to_wasi(errno));
    }
    filestat->dev = fd_stat.st_dev;
    filestat->ino = fd_stat.st_ino;
    int mode = fd_stat.st_mode;
    filestat->filetype = (S_ISBLK(mode)   ? __WASI_FILETYPE_BLOCK_DEVICE     : 0) |
                          (S_ISCHR(mode)   ? __WASI_FILETYPE_CHARACTER_DEVICE : 0) |
                          (S_ISDIR(mode)   ? __WASI_FILETYPE_DIRECTORY        : 0) |
                          (S_ISREG(mode)   ? __WASI_FILETYPE_REGULAR_FILE     : 0) |
                          //(S_ISSOCK(mode)  ? __WASI_FILETYPE_SOCKET_STREAM    : 0) |
                          (S_ISLNK(mode)   ? __WASI_FILETYPE_SYMBOLIC_LINK    : 0);
    filestat->nlink = fd_stat.st_nlink;
    filestat->size = fd_stat.st_size;
    filestat->atim = fd_stat.st_atimespec.tv_sec * 1e9 + fd_stat.st_atimespec.tv_nsec;
    filestat->mtim = fd_stat.st_mtimespec.tv_sec * 1e9 + fd_stat.st_mtimespec.tv_nsec;
    filestat->ctim = fd_stat.st_ctimespec.tv_sec * 1e9 + fd_stat.st_ctimespec.tv_nsec;
    
    m3ApiReturn(__WASI_ERRNO_SUCCESS);
}

m3ApiRawFunction(m3_wasi_snapshot_preview1_path_filestat_get)
{
    // "i(ii*i*)"
    // fd, flags, pathPtr, pathLen, bufPtr
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , fd)
    m3ApiGetArg      (__wasi_fstflags_t    , fst_flags)
    m3ApiGetArgMem   (char *               , path)
    m3ApiGetArg      (__wasi_size_t        , path_len)
    m3ApiGetArgMem   (__wasi_filestat_t *    , filestat)

    m3ApiCheckMem(path, path_len);
    m3ApiCheckMem(filestat, sizeof(__wasi_filestat_t));
    
    struct stat fd_stat;

    // copy path so we can ensure it is NULL terminated
#if defined(M3_COMPILER_MSVC)
    char host_path[512];
#else
    char host_path[path_len+1];
#endif
    memcpy (host_path, path, path_len);
    host_path[path_len] = '\0'; // NULL terminator
    int returnValue = stat(host_path, &fd_stat);
    if (returnValue < 0) {
        m3ApiReturn(errno_to_wasi(errno));
    }

    filestat->dev = fd_stat.st_dev;
    filestat->ino = fd_stat.st_ino;
    int mode = fd_stat.st_mode;
    filestat->filetype = (S_ISBLK(mode)   ? __WASI_FILETYPE_BLOCK_DEVICE     : 0) |
                          (S_ISCHR(mode)   ? __WASI_FILETYPE_CHARACTER_DEVICE : 0) |
                          (S_ISDIR(mode)   ? __WASI_FILETYPE_DIRECTORY        : 0) |
                          (S_ISREG(mode)   ? __WASI_FILETYPE_REGULAR_FILE     : 0) |
                          //(S_ISSOCK(mode)  ? __WASI_FILETYPE_SOCKET_STREAM    : 0) |
                          (S_ISLNK(mode)   ? __WASI_FILETYPE_SYMBOLIC_LINK    : 0);
    filestat->nlink = fd_stat.st_nlink;
    filestat->size = fd_stat.st_size;
    filestat->atim = fd_stat.st_atimespec.tv_sec * 1e9 + fd_stat.st_atimespec.tv_nsec;
    filestat->mtim = fd_stat.st_mtimespec.tv_sec * 1e9 + fd_stat.st_mtimespec.tv_nsec;
    filestat->ctim = fd_stat.st_ctimespec.tv_sec * 1e9 + fd_stat.st_ctimespec.tv_nsec;

    m3ApiReturn(__WASI_ERRNO_SUCCESS);
}

m3ApiRawFunction(m3_wasi_generic_fd_advise)
{
    // fd, offset, len, advice: iIIi
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , fd)
    m3ApiGetArg      (__wasi_filesize_t    , offset)
    m3ApiGetArg      (__wasi_filesize_t    , len)
    m3ApiGetArg      (__wasi_advice_t      , advice)

    if (offset < 0 || len < 0)
        m3ApiReturn(__WASI_ERRNO_INVAL);

#if TARGET_OS_IPHONE
    if (fd == STDIN_FILENO)
        fd = fileno(thread_stdin);
    else if (fd == STDOUT_FILENO)
        fd = fileno(thread_stdout);
    else if (fd == STDERR_FILENO)
        fd = fileno(thread_stderr);
#endif
    if (fd < 3) // tty, not permitted
        m3ApiReturn(__WASI_ERRNO_PERM);

    struct stat fd_stat;
    fstat(fd, &fd_stat);
    int mode = fd_stat.st_mode;
    // Advise is not a right for: tty, socket.
    if (S_ISSOCK(mode)) {
        m3ApiReturn(__WASI_ERRNO_PERM);
    }
    m3ApiReturn(__WASI_ERRNO_NOSYS);
}

m3ApiRawFunction(m3_wasi_generic_fd_filestat_set_times)
{
    // fd, atim, mtim, fst_flags: iIIi
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , fd)
    m3ApiGetArg      (__wasi_timestamp_t   , atim)
    // m3ApiGetArg      (__wasi_timestamp_t   , atim_ns)
    m3ApiGetArg      (__wasi_timestamp_t   , mtim)
    // m3ApiGetArg      (__wasi_timestamp_t   , mtim_ns)
    m3ApiGetArg      (__wasi_fstflags_t    , fst_flags)

    // Rewrite. it's fd, stAtim, stAtim_ns, stMtim, stMtim_ns, fstflags
    // or iIIIIi
    
#if TARGET_OS_IPHONE
    if (fd == STDIN_FILENO)
        fd = fileno(thread_stdin);
    else if (fd == STDOUT_FILENO)
        fd = fileno(thread_stdout);
    else if (fd == STDERR_FILENO)
        fd = fileno(thread_stderr);
#endif
    struct timeval time[2];
    if (fst_flags & __WASI_FSTFLAGS_ATIM_NOW) {
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        time[0].tv_sec = now.tv_sec;
        time[0].tv_usec = now.tv_nsec / 1000;
    } else {
        time[0].tv_sec = atim / 1000000000;
        time[0].tv_usec = (atim % 1000000000) / 1000;
    }
    if (fst_flags & __WASI_FSTFLAGS_MTIM_NOW) {
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        time[1].tv_sec = now.tv_sec;
        time[1].tv_usec = now.tv_nsec / 1000;
    } else {
        time[1].tv_sec = mtim / 1000000000;
        time[1].tv_usec = (mtim % 1000000000) / 1000;
    }
    int returnVal = futimes(fd, time);
    if (returnVal == 0)
        m3ApiReturn(__WASI_ERRNO_SUCCESS);
    m3ApiReturn(errno_to_wasi(errno));
}

m3ApiRawFunction(m3_wasi_generic_fd_allocate)
{
    // fd, offset, len: iII
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , fd)
    m3ApiGetArg      (__wasi_filesize_t    , offset)
    m3ApiGetArg      (__wasi_filesize_t    , len)

    if (offset < 0 || len < 0)
        m3ApiReturn(__WASI_ERRNO_INVAL);

#if TARGET_OS_IPHONE
    if (fd == STDIN_FILENO)
        fd = fileno(thread_stdin);
    else if (fd == STDOUT_FILENO)
        fd = fileno(thread_stdout);
    else if (fd == STDERR_FILENO)
        fd = fileno(thread_stderr);
#endif
    if (fd < 3) // tty, not permitted
        m3ApiReturn(__WASI_ERRNO_PERM);

    struct stat fd_stat;
    fstat(fd, &fd_stat);
    int mode = fd_stat.st_mode;
    // Allocate is not a right for: tty, dir, socket.
    if (S_ISSOCK(mode)) {
        m3ApiReturn(__WASI_ERRNO_PERM);
    }
    if (S_ISDIR(mode)) {
        m3ApiReturn(__WASI_ERRNO_PERM);
    }
    m3ApiReturn(__WASI_ERRNO_NOSYS);
}

m3ApiRawFunction(m3_wasi_generic_path_unlink)
{
    //i(i*i) // fd, pathPtr, pathLen
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , fd)
    m3ApiGetArgMem   (char *               , path)
    m3ApiGetArg      (__wasi_size_t        , path_len)

    m3ApiCheckMem(path, path_len);

    if (unlink(path) == 0)
        m3ApiReturn(__WASI_ERRNO_SUCCESS);
    m3ApiReturn(errno_to_wasi(errno));
}

m3ApiRawFunction(m3_wasi_generic_ashell_getcwd)
{
    // i(*ii)
    // buf, bufLen, bufused
    m3ApiReturnType  (uint32_t)
    m3ApiGetArgMem   (char *               , path)
    m3ApiGetArg      (__wasi_size_t        , path_len)
    m3ApiGetArgMem   (__wasi_size_t *      , retptr0)

    m3ApiCheckMem(path, path_len);

    getcwd(path, path_len);
    m3ApiWriteMem64(retptr0, strlen(path));
    m3ApiReturn(__WASI_ERRNO_SUCCESS);
}

m3ApiRawFunction(m3_wasi_generic_ashell_chdir)
{
    // i(*i)
    // buf, bufLen
    m3ApiReturnType  (uint32_t)
    m3ApiGetArgMem   (char *               , path)
    m3ApiGetArg      (__wasi_size_t        , path_len)

    m3ApiCheckMem(path, path_len);

    if (chdir(path) == 0)
        m3ApiReturn(__WASI_ERRNO_SUCCESS);
    m3ApiReturn(errno_to_wasi(errno));
}

m3ApiRawFunction(m3_wasi_generic_ashell_fchdir)
{
    // i(i)
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , fd)

    if (fchdir(fd) == 0)
        m3ApiReturn(__WASI_ERRNO_SUCCESS);
    m3ApiReturn(errno_to_wasi(errno));
}

m3ApiRawFunction(m3_wasi_generic_ashell_system)
{
    // i(*i)
    // buf, bufLen
    m3ApiReturnType  (uint32_t)
    m3ApiGetArgMem   (char *               , command)
    m3ApiGetArg      (__wasi_size_t        , command_len)

    m3ApiCheckMem(command, command_len);

    int pid = ios_fork();
    int result = ios_system(command);
    ios_waitpid(pid);
    ios_releaseThreadId(pid);
    if (result == 0) {
        // If there's already been an error (e.g. "command not found") no need to ask for more.
        result = ios_getCommandStatus();
    }
    m3ApiReturn(result);
}

m3ApiRawFunction(m3_wasi_generic_ashell_getenv)
{
    // i(*i*i*)
    // variablePtr, variableLen, buf, bufLen, bufused
    m3ApiReturnType  (uint32_t)
    m3ApiGetArgMem   (char *               , variable)
    m3ApiGetArg      (__wasi_size_t        , variable_len)
    m3ApiGetArgMem   (char *               , result)
    m3ApiGetArg      (__wasi_size_t        , result_len)
    m3ApiGetArg      (__wasi_size_t *      , result_used)
    
    m3ApiCheckMem(variable, variable_len);
    m3ApiCheckMem(result, result_len);
    char* res = ios_getenv(variable);
    
    if (res != NULL) {
        strcpy(result, res);
        // m3ApiWriteMem32(result_used, strlen(res));
    } else {
        // m3ApiWriteMem32(result_used, 0);
    }
    m3ApiReturn(__WASI_ERRNO_SUCCESS);
}

m3ApiRawFunction(m3_wasi_generic_ashell_setenv)
{
    // i(*i*ii)
    // variablePtr, variableLen, buf, bufLen, bufused
    m3ApiReturnType  (uint32_t)
    m3ApiGetArgMem   (char *               , variable)
    m3ApiGetArg      (__wasi_size_t        , variable_len)
    m3ApiGetArgMem   (char *               , value)
    m3ApiGetArg      (__wasi_size_t        , value_len)
    m3ApiGetArg      (uint32_t             , force)
    
    m3ApiCheckMem(variable, variable_len);
    m3ApiCheckMem(value, value_len);
    if (ios_setenv(variable, value, force) == 0)
        m3ApiReturn(__WASI_ERRNO_SUCCESS);
    m3ApiReturn(errno_to_wasi(errno));
}

m3ApiRawFunction(m3_wasi_generic_ashell_unsetenv)
{
    // i(*i)
    // variablePtr, variableLen, buf, bufLen, bufused
    m3ApiReturnType  (uint32_t)
    m3ApiGetArgMem   (char *               , variable)
    m3ApiGetArg      (__wasi_size_t        , variable_len)
    
    m3ApiCheckMem(variable, variable_len);
    if (ios_unsetenv(variable) == 0)
        m3ApiReturn(__WASI_ERRNO_SUCCESS);
    m3ApiReturn(errno_to_wasi(errno));
}

static
M3Result SuppressLookupFailure(M3Result i_result)
{
    if (i_result == m3Err_functionLookupFailed)
        return m3Err_none;
    else
        return i_result;
}

m3_wasi_context_t* m3_GetWasiContext()
{
    return wasi_context;
}


M3Result  m3_LinkWASI  (IM3Module module)
{
    M3Result result = m3Err_none;

#ifdef _WIN32
    setmode(fileno(stdin),  O_BINARY);
    setmode(fileno(stdout), O_BINARY);
    setmode(fileno(stderr), O_BINARY);

#else
    // Preopen dirs
    for (int i = 3; i < PREOPEN_CNT; i++) {
        preopen[i].fd = open(preopen[i].real_path, O_RDONLY);
    }
#endif

    if (!wasi_context) {
        wasi_context = (m3_wasi_context_t*)malloc(sizeof(m3_wasi_context_t));
        wasi_context->exit_code = 0;
        wasi_context->argc = 0;
        wasi_context->argv = 0;
    }

    static const char* namespaces[2] = { "wasi_unstable", "wasi_snapshot_preview1" };

    // Some functions are incompatible between WASI versions
_   (SuppressLookupFailure (m3_LinkRawFunction (module, "wasi_unstable",          "fd_seek",     "i(iIi*)", &m3_wasi_unstable_fd_seek)));
_   (SuppressLookupFailure (m3_LinkRawFunction (module, "wasi_snapshot_preview1", "fd_seek",     "i(iIi*)", &m3_wasi_snapshot_preview1_fd_seek)));
//_ (SuppressLookupFailure (m3_LinkRawFunction (module, "wasi_unstable",          "fd_filestat_get",   "i(i*)",     &m3_wasi_unstable_fd_filestat_get)));
_   (SuppressLookupFailure (m3_LinkRawFunction (module, "wasi_snapshot_preview1", "fd_filestat_get",   "i(i*)",     &m3_wasi_snapshot_preview1_fd_filestat_get)));
//_ (SuppressLookupFailure (m3_LinkRawFunction (module, "wasi_unstable",          "path_filestat_get", "i(ii*i*)",  &m3_wasi_unstable_path_filestat_get)));
_   (SuppressLookupFailure (m3_LinkRawFunction (module, "wasi_snapshot_preview1", "path_filestat_get", "i(ii*i*)",  &m3_wasi_snapshot_preview1_path_filestat_get)));

    for (int i=0; i<2; i++)
    {
        const char* wasi = namespaces[i];

_       (SuppressLookupFailure (m3_LinkRawFunctionEx (module, wasi, "args_get",           "i(**)",   &m3_wasi_generic_args_get, wasi_context)));
_       (SuppressLookupFailure (m3_LinkRawFunctionEx (module, wasi, "args_sizes_get",     "i(**)",   &m3_wasi_generic_args_sizes_get, wasi_context)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "clock_res_get",        "i(i*)",   &m3_wasi_generic_clock_res_get)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "clock_time_get",       "i(iI*)",  &m3_wasi_generic_clock_time_get)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "environ_get",          "i(**)",   &m3_wasi_generic_environ_get)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "environ_sizes_get",    "i(**)",   &m3_wasi_generic_environ_sizes_get)));

_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "fd_advise",            "i(iIIi)", &m3_wasi_generic_fd_advise)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "fd_allocate",          "i(iII)",  &m3_wasi_generic_fd_allocate)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "fd_close",             "i(i)",    &m3_wasi_generic_fd_close)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "fd_datasync",          "i(i)",    &m3_wasi_generic_fd_datasync)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "fd_fdstat_get",        "i(i*)",   &m3_wasi_generic_fd_fdstat_get)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "fd_fdstat_set_flags",  "i(ii)",   &m3_wasi_generic_fd_fdstat_set_flags)));
//_     (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "fd_fdstat_set_rights", "i(iII)",  )));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "fd_filestat_set_size", "i(iI)",   &m3_wasi_generic_fd_filestat_set_size)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "fd_filestat_set_times","i(iIIi)", &m3_wasi_generic_fd_filestat_set_times)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "fd_pread",             "i(i*iI*)", &m3_wasi_generic_fd_pread)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "fd_prestat_get",       "i(i*)",   &m3_wasi_generic_fd_prestat_get)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "fd_prestat_dir_name",  "i(i*i)",  &m3_wasi_generic_fd_prestat_dir_name)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "fd_pwrite",            "i(i*iI*)",&m3_wasi_generic_fd_pwrite)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "fd_read",              "i(i*i*)", &m3_wasi_generic_fd_read)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "fd_readdir",           "i(i*iI*)",&m3_wasi_generic_fd_readdir)));
//_     (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "fd_renumber",          "i(ii)",   ))); // used by freopen. Tricky.
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "fd_sync",              "i(i)",    &m3_wasi_generic_fd_sync)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "fd_tell",              "i(i*)",   &m3_wasi_generic_fd_tell)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "fd_write",             "i(i*i*)", &m3_wasi_generic_fd_write)));

_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "path_create_directory",    "i(i*i)", &m3_wasi_generic_path_create_directory)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "path_filestat_set_times",  "i(ii*iIIi)", &m3_wasi_generic_path_filestat_set_times)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "path_link",                "i(ii*ii*i)",   &m3_wasi_generic_path_link)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "path_open",                "i(ii*iiIIi*)", &m3_wasi_generic_path_open)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "path_readlink",            "i(i*i*i*)",    &m3_wasi_generic_path_readlink)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "path_remove_directory",    "i(i*i)",       &m3_wasi_generic_path_remove_directory)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "path_rename",              "i(i*ii*i)",    &m3_wasi_generic_path_rename)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "path_symlink",             "i(*ii*i)",     &m3_wasi_generic_path_symlink)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "path_unlink_file",         "i(i*i)",       &m3_wasi_generic_path_unlink)));

//_     (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "poll_oneoff",          "i(**i*)", &m3_wasi_generic_poll_oneoff))); // TODO?
_       (SuppressLookupFailure (m3_LinkRawFunctionEx (module, wasi, "proc_exit",          "v(i)",    &m3_wasi_generic_proc_exit, wasi_context)));
//_     (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "proc_raise",           "i(i)",    )));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "random_get",           "i(*i)",   &m3_wasi_generic_random_get)));
//_     (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "sched_yield",          "i()",     )));

//_     (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "sock_recv",            "i(i*ii**)",        )));
//_     (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "sock_send",            "i(i*ii*)",         )));
//_     (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "sock_shutdown",        "i(ii)",            )));
        // a-Shell specific additions
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "ashell_getcwd",        "i(*ii)",     &m3_wasi_generic_ashell_getcwd)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "ashell_chdir",         "i(*i)",      &m3_wasi_generic_ashell_chdir)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "ashell_fchdir",        "i(i)",       &m3_wasi_generic_ashell_fchdir)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "ashell_system",        "i(*i)",      &m3_wasi_generic_ashell_system)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "ashell_getenv",        "i(*i*i*)",   &m3_wasi_generic_ashell_getenv)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "ashell_setenv",        "i(*i*ii)",   &m3_wasi_generic_ashell_setenv)));
_       (SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "ashell_unsetenv",      "i(*i)",      &m3_wasi_generic_ashell_unsetenv)));
    }

_catch:
    return result;
}

#endif // d_m3HasWASI
