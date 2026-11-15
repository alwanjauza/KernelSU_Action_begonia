#!/usr/bin/env python3
"""Apply BakaSU manual hooks to the begonia 4.14 kernel tree.

Only the hooks that BakaSU checks unconditionally are patched. The setuid,
init.rc and input hooks are handled by BakaSU's own LSM handlers
(CONFIG_KSU_MANUAL_HOOK_AUTO_* default to y on 4.14), so those files are left
alone on purpose.

Run from the kernel source root. Idempotent: skips files already patched.
"""
import sys
from pathlib import Path

ROOT = Path(".")

EXEC_DECL = """#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,
			       void *argv, void *envp, int *flags);
__attribute__((hot))
extern int ksu_handle_post_execveat(int *fd, struct filename **filename_ptr,
				    void *argv, void *envp, int *flags, int *retval);
#endif

"""

STAT_DECL = """#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);
extern void ksu_handle_newfstat_ret(unsigned int *fd, struct stat __user **statbuf_ptr);
#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
extern void ksu_handle_fstat64_ret(unsigned long *fd, struct stat64 __user **statbuf_ptr);
#endif
#endif

"""

OPEN_DECL = """#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,
				int *mode, int *flags);
#endif

"""

REBOOT_DECL = """#ifdef CONFIG_KSU_MANUAL_HOOK
extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);
#endif

"""


def fail(msg):
    print(f"[!] {msg}")
    sys.exit(1)


def patch(path, edits):
    p = ROOT / path
    if not p.exists():
        fail(f"{path} not found")
    src = p.read_text()
    if "ksu_handle" in src:
        print(f"[-] {path} already patched, skipping")
        return
    for old, new in edits:
        if old not in src:
            fail(f"{path}: anchor not found -> {old.splitlines()[0][:60]!r}")
        src = src.replace(old, new, 1)
    p.write_text(src)
    print(f"[+] {path} patched")


def main():
    patch("fs/exec.c", [
        ("static int __do_execve_file(int fd, struct filename *filename,",
         EXEC_DECL + "static int __do_execve_file(int fd, struct filename *filename,"),
        ("\tstruct files_struct *displaced;\n\tint retval;\n\n\tif (IS_ERR(filename))",
         "\tstruct files_struct *displaced;\n\tint retval;\n\n"
         "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
         "\tksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);\n"
         "#endif\n\n"
         "\tif (IS_ERR(filename))"),
        ("out_ret:\n\tif (filename)\n\t\tputname(filename);",
         "out_ret:\n"
         "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
         "\tksu_handle_post_execveat(&fd, &filename, &argv, &envp, &flags, &retval);\n"
         "#endif\n"
         "\tif (filename)\n\t\tputname(filename);"),
    ])

    patch("fs/open.c", [
        ("SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)\n{",
         OPEN_DECL +
         "SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)\n{"),
        ("\tint res;\n\tunsigned int lookup_flags = LOOKUP_FOLLOW;\n\n\tif (mode & ~S_IRWXO)",
         "\tint res;\n\tunsigned int lookup_flags = LOOKUP_FOLLOW;\n\n"
         "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
         "\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);\n"
         "#endif\n\n"
         "\tif (mode & ~S_IRWXO)"),
    ])

    patch("fs/stat.c", [
        ("SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,",
         STAT_DECL + "SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,"),
        ("SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,\n"
         "\t\tstruct stat __user *, statbuf, int, flag)\n{\n\tstruct kstat stat;\n\tint error;\n",
         "SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,\n"
         "\t\tstruct stat __user *, statbuf, int, flag)\n{\n\tstruct kstat stat;\n\tint error;\n\n"
         "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
         "\tksu_handle_stat(&dfd, &filename, &flag);\n"
         "#endif\n"),
        ("SYSCALL_DEFINE2(newfstat, unsigned int, fd, struct stat __user *, statbuf)\n{\n"
         "\tstruct kstat stat;\n\tint error = vfs_fstat(fd, &stat);\n\n"
         "\tif (!error)\n\t\terror = cp_new_stat(&stat, statbuf);\n",
         "SYSCALL_DEFINE2(newfstat, unsigned int, fd, struct stat __user *, statbuf)\n{\n"
         "\tstruct kstat stat;\n\tint error = vfs_fstat(fd, &stat);\n\n"
         "\tif (!error)\n\t\terror = cp_new_stat(&stat, statbuf);\n\n"
         "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
         "\tksu_handle_newfstat_ret(&fd, &statbuf);\n"
         "#endif\n"),
        ("SYSCALL_DEFINE4(fstatat64, int, dfd, const char __user *, filename,\n"
         "\t\tstruct stat64 __user *, statbuf, int, flag)\n{\n\tstruct kstat stat;\n\tint error;\n",
         "SYSCALL_DEFINE4(fstatat64, int, dfd, const char __user *, filename,\n"
         "\t\tstruct stat64 __user *, statbuf, int, flag)\n{\n\tstruct kstat stat;\n\tint error;\n\n"
         "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
         "\tksu_handle_stat(&dfd, &filename, &flag);\n"
         "#endif\n"),
        ("SYSCALL_DEFINE2(fstat64, unsigned long, fd, struct stat64 __user *, statbuf)\n{\n"
         "\tstruct kstat stat;\n\tint error = vfs_fstat(fd, &stat);\n\n"
         "\tif (!error)\n\t\terror = cp_new_stat64(&stat, statbuf);\n",
         "SYSCALL_DEFINE2(fstat64, unsigned long, fd, struct stat64 __user *, statbuf)\n{\n"
         "\tstruct kstat stat;\n\tint error = vfs_fstat(fd, &stat);\n\n"
         "\tif (!error)\n\t\terror = cp_new_stat64(&stat, statbuf);\n\n"
         "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
         "\tksu_handle_fstat64_ret(&fd, &statbuf);\n"
         "#endif\n"),
    ])

    patch("kernel/reboot.c", [
        ("SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,",
         REBOOT_DECL + "SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,"),
        ("\tchar buffer[256];\n\tint ret = 0;\n\n\t/* We only trust the superuser",
         "\tchar buffer[256];\n\tint ret = 0;\n\n"
         "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
         "\tksu_handle_sys_reboot(magic1, magic2, cmd, &arg);\n"
         "#endif\n\n"
         "\t/* We only trust the superuser"),
    ])

    print("[+] all required hooks applied")


if __name__ == "__main__":
    main()
