//!Implementation of [`TaskManager`]
use super::TaskControlBlock;
use crate::sync::UPSafeCell;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use lazy_static::*;
///A array of `TaskControlBlock` that is thread-safe
pub struct TaskManager {
    ready_queue: VecDeque<Arc<TaskControlBlock>>,
}

/// Compare stride values under wrapping arithmetic.
fn stride_less(lhs: usize, rhs: usize) -> bool {
    lhs != rhs && lhs.wrapping_sub(rhs) > usize::MAX / 2
}

/// A stride scheduler.
impl TaskManager {
    ///Creat an empty TaskManager
    pub fn new() -> Self {
        Self {
            ready_queue: VecDeque::new(),
        }
    }
    /// Add process back to ready queue
    pub fn add(&mut self, task: Arc<TaskControlBlock>) {
        self.ready_queue.push_back(task);
    }
    /// Take a process out of the ready queue.
    pub fn fetch(&mut self) -> Option<Arc<TaskControlBlock>> {
        if self.ready_queue.is_empty() {
            return None;
        }
        let mut best_idx = 0usize;
        let mut best_stride = self.ready_queue[0].stride();
        let mut best_pid = self.ready_queue[0].getpid();
        for i in 1..self.ready_queue.len() {
            let task = &self.ready_queue[i];
            let task_stride = task.stride();
            let task_pid = task.getpid();
            if stride_less(task_stride, best_stride)
                || (task_stride == best_stride && task_pid < best_pid)
            {
                best_idx = i;
                best_stride = task_stride;
                best_pid = task_pid;
            }
        }
        let task = self.ready_queue.remove(best_idx).unwrap();
        task.advance_stride();
        Some(task)
    }
}

lazy_static! {
    /// TASK_MANAGER instance through lazy_static!
    pub static ref TASK_MANAGER: UPSafeCell<TaskManager> =
        unsafe { UPSafeCell::new(TaskManager::new()) };
}

/// Add process to ready queue
pub fn add_task(task: Arc<TaskControlBlock>) {
    //trace!("kernel: TaskManager::add_task");
    TASK_MANAGER.exclusive_access().add(task);
}

/// Take a process out of the ready queue
pub fn fetch_task() -> Option<Arc<TaskControlBlock>> {
    //trace!("kernel: TaskManager::fetch_task");
    TASK_MANAGER.exclusive_access().fetch()
}
