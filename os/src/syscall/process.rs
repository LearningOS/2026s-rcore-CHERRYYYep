//! Process management syscalls
use crate::config::PAGE_SIZE;
use crate::mm::{MapPermission, PTEFlags, PageTable, VirtAddr};
use crate::task::{
    change_program_brk, current_syscall_count, exit_current_and_run_next, get_current_token,
    mmap_current, munmap_current, suspend_current_and_run_next,
};
use crate::timer::get_time_us;
use core::slice;

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

fn current_task_user_pte(addr: usize) -> Option<crate::mm::PageTableEntry> {
    let token = get_current_token();
    let page_table = PageTable::from_token(token);
    page_table.translate(VirtAddr::from(addr).floor())
}

fn write_user_bytes(mut addr: usize, mut bytes: &[u8]) -> bool {
    while !bytes.is_empty() {
        let va = VirtAddr::from(addr);
        let offset = va.page_offset();
        let writable_len = bytes.len().min(4096 - offset);
        let Some(pte) = current_task_user_pte(addr) else {
            return false;
        };
        let flags = pte.flags();
        if !flags.contains(PTEFlags::U) || !pte.writable() {
            return false;
        }
        let dst = &mut pte.ppn().get_bytes_array()[offset..offset + writable_len];
        dst.copy_from_slice(&bytes[..writable_len]);
        addr += writable_len;
        bytes = &bytes[writable_len..];
    }
    true
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let us = get_time_us();
    let timeval = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };
    let bytes = unsafe {
        slice::from_raw_parts(
            &timeval as *const TimeVal as *const u8,
            core::mem::size_of::<TimeVal>(),
        )
    };
    if write_user_bytes(ts as usize, bytes) {
        0
    } else {
        -1
    }
}

/// TODO: Finish sys_trace to pass testcases
/// HINT: You might reimplement it with virtual memory management.
pub fn sys_trace(trace_request: usize, id: usize, data: usize) -> isize {
    match trace_request {
        0 => {
            if let Some(pte) = current_task_user_pte(id) {
                let flags = pte.flags();
                if flags.contains(PTEFlags::U) && pte.readable() {
                    let offset = VirtAddr::from(id).page_offset();
                    return pte.ppn().get_bytes_array()[offset] as isize;
                }
            }
            -1
        }
        1 => {
            if write_user_bytes(id, &[data as u8]) {
                return 0;
            }
            -1
        }
        2 => current_syscall_count(id) as isize,
        _ => -1,
    }
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    trace!("kernel: sys_mmap");
    if len == 0 || start % PAGE_SIZE != 0 || port == 0 || (port & !0x7) != 0 {
        return -1;
    }
    let mut permission = MapPermission::U;
    if (port & 0x1) != 0 {
        permission |= MapPermission::R;
    }
    if (port & 0x2) != 0 {
        permission |= MapPermission::W;
    }
    if (port & 0x4) != 0 {
        permission |= MapPermission::X;
    }
    if mmap_current(start, len, permission) {
        0
    } else {
        -1
    }
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap");
    if len == 0 || start % PAGE_SIZE != 0 {
        return -1;
    }
    if start.checked_add(len).is_none() {
        return -1;
    }
    if munmap_current(start, len) {
        0
    } else {
        -1
    }
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
