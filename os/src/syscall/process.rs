//! Process management syscalls
use alloc::sync::Arc;
use core::{cmp::min, mem::size_of, slice};

use crate::{
    config::PAGE_SIZE,
    loader::get_app_data_by_name,
    mm::{MapPermission, PageTableEntry, VirtAddr, translated_refmut, translated_str},
    task::{
        TaskControlBlock, add_task, current_syscall_count, current_task, current_user_token, exit_current_and_run_next, mmap_current, munmap_current, set_current_priority, suspend_current_and_run_next
    },
    timer::get_time_us,
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

fn current_task_user_pte(va: usize) -> Option<PageTableEntry> {
    let task = current_task()?;
    let inner = task.inner_exclusive_access();
    let pte = inner.memory_set.translate(VirtAddr::from(va).floor())?;
    if !pte.is_valid() {
        return None;
    }
    Some(pte)
}

fn write_user_bytes(dst: *mut u8, src: &[u8]) -> bool {
    let base = dst as usize;
    let mut offset = 0usize;
    while offset < src.len() {
        let va = match base.checked_add(offset) {
            Some(v) => v,
            None => return false,
        };
        let pte = match current_task_user_pte(va) {
            Some(p) => p,
            None => return false,
        };
        // Ensure user space page and writable page.
        if !pte.writable() || !pte.user() {
            return false;
        }
        let page_off = VirtAddr::from(va).page_offset();
        let write_len = min(PAGE_SIZE - page_off, src.len() - offset);
        let page = pte.ppn().get_bytes_array();
        page[page_off..page_off + write_len].copy_from_slice(&src[offset..offset + write_len]);
        offset += write_len;
    }
    true
}

fn read_user_u8(src: *const u8) -> Option<u8> {
    let va = src as usize;
    let pte = current_task_user_pte(va)?;
    if !pte.readable() || !pte.user() {
        return None;
    }
    let page = pte.ppn().get_bytes_array();
    Some(page[VirtAddr::from(va).page_offset()])
}

fn write_user_u8(dst: *mut u8, value: u8) -> bool {
    let va = dst as usize;
    let pte = match current_task_user_pte(va) {
        Some(pte) => pte,
        None => return false,
    };
    if !pte.writable() || !pte.user() {
        return false;
    }
    let page = pte.ppn().get_bytes_array();
    page[VirtAddr::from(va).page_offset()] = value;
    true
}

/// task exits and submit an exit code
pub fn sys_exit(exit_code: i32) -> ! {
    trace!("kernel:pid[{}] sys_exit", current_task().unwrap().pid.0);
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel:pid[{}] sys_yield", current_task().unwrap().pid.0);
    suspend_current_and_run_next();
    0
}

pub fn sys_getpid() -> isize {
    trace!("kernel: sys_getpid pid:{}", current_task().unwrap().pid.0);
    current_task().unwrap().pid.0 as isize
}

pub fn sys_fork() -> isize {
    trace!("kernel:pid[{}] sys_fork", current_task().unwrap().pid.0);
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

pub fn sys_exec(path: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_exec", current_task().unwrap().pid.0);
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(data) = get_app_data_by_name(path.as_str()) {
        let task = current_task().unwrap();
        task.exec(data);
        0
    } else {
        -1
    }
}

/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    trace!("kernel::pid[{}] sys_waitpid [{}]", current_task().unwrap().pid.0, pid);
    let task = current_task().unwrap();
    // find a child process

    // ---- access current PCB exclusively
    let mut inner = task.inner_exclusive_access();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.getpid())
    {
        return -1;
        // ---- release current PCB
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily access child PCB exclusively
        p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after being removed from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily access child PCB exclusively
        let exit_code = child.inner_exclusive_access().exit_code;
        // ++++ release child PCB
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB automatically
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel:pid[{}] sys_get_time", current_task().unwrap().pid.0);
    if ts.is_null() {
        return -1;
    }
    let us = get_time_us();
    let tv = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };
    let tv_bytes = unsafe { slice::from_raw_parts((&tv as *const TimeVal).cast::<u8>(), size_of::<TimeVal>()) };
    if write_user_bytes(ts.cast::<u8>(), tv_bytes) {
        0
    } else {
        -1
    }
}

/// syscall trace helper.
/// request = 0: read 1 byte from user address `id`
/// request = 1: write low 8-bit of `data` to user address `id`
/// request = 2: query syscall count of syscall id `id`
pub fn sys_trace(request: usize, id: usize, data: usize) -> isize {
    trace!(
        "kernel:pid[{}] sys_trace request={}",
        current_task().unwrap().pid.0,
        request
    );
    match request {
        0 => read_user_u8(id as *const u8).map(|b| b as isize).unwrap_or(-1),
        1 => {
            if write_user_u8(id as *mut u8, data as u8) {
                0
            } else {
                -1
            }
        }
        2 => current_syscall_count(id),
        _ => -1,
    }
}

/// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    trace!("kernel:pid[{}] sys_mmap", current_task().unwrap().pid.0);
    if len == 0 {
        return -1;
    }
    if !VirtAddr::from(start).aligned() {
        return -1;
    }
    if start.checked_add(len).is_none() {
        return -1;
    }
    if port == 0 || port & !0b111 != 0 {
        return -1;
    }
    let mut permission = MapPermission::U;
    if (port & 0b001) != 0 {
        permission |= MapPermission::R;
    }
    if (port & 0b010) != 0 {
        permission |= MapPermission::W;
    }
    if (port & 0b100) != 0 {
        permission |= MapPermission::X;
    }
    mmap_current(start, len, permission)
}

/// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel:pid[{}] sys_munmap", current_task().unwrap().pid.0);
    if len == 0 {
        return -1;
    }
    if !VirtAddr::from(start).aligned() {
        return -1;
    }
    if start.checked_add(len).is_none() {
        return -1;
    }
    munmap_current(start, len)
}

/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel:pid[{}] sys_sbrk", current_task().unwrap().pid.0);
    if let Some(old_brk) = current_task().unwrap().change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}

/// YOUR JOB: Implement spawn.
/// HINT: fork + exec =/= spawn
pub fn sys_spawn(path: *const u8) -> isize {
    let token = current_user_token();
    let path = translated_str(token, path);
    let Some(elf_data) = get_app_data_by_name(path.as_str()) else {
        return -1;
    };
    
    let current_task = current_task().unwrap();
    let new_task = Arc::new(TaskControlBlock::new(elf_data));
    let new_pid = new_task.pid.0;

    new_task.inner_exclusive_access().parent = Some(Arc::downgrade(&current_task));
    current_task.inner_exclusive_access().children.push(new_task.clone());

    add_task(new_task);
    new_pid as isize
}

/// Set current task priority for stride scheduler.
pub fn sys_set_priority(prio: isize) -> isize {
    trace!("kernel:pid[{}] sys_set_priority", current_task().unwrap().pid.0);
    set_current_priority(prio)
}
