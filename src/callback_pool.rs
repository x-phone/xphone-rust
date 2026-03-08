//! A lightweight thread pool for dispatching callbacks.
//!
//! Instead of spawning a new OS thread for each callback invocation,
//! tasks are sent to a fixed pool of worker threads via a crossbeam channel.
//! Falls back to `std::thread::spawn` if the pool channel is full.

use std::sync::LazyLock;

use crossbeam_channel::{bounded, Sender};

/// Number of worker threads in the callback pool.
const POOL_SIZE: usize = 4;

/// Max queued callbacks before falling back to thread::spawn.
const QUEUE_CAPACITY: usize = 1024;

static POOL: LazyLock<Sender<Box<dyn FnOnce() + Send + 'static>>> = LazyLock::new(|| {
    let (tx, rx) = bounded::<Box<dyn FnOnce() + Send + 'static>>(QUEUE_CAPACITY);
    for i in 0..POOL_SIZE {
        let rx = rx.clone();
        std::thread::Builder::new()
            .name(format!("xphone-cb-{}", i))
            .spawn(move || {
                while let Ok(task) = rx.recv() {
                    task();
                }
            })
            .expect("failed to spawn callback pool thread");
    }
    tx
});

/// Dispatch a callback on the shared pool. If the pool queue is full,
/// falls back to spawning a dedicated thread to avoid blocking the caller.
pub fn spawn_callback(f: impl FnOnce() + Send + 'static) {
    let boxed: Box<dyn FnOnce() + Send + 'static> = Box::new(f);
    match POOL.try_send(boxed) {
        Err(crossbeam_channel::TrySendError::Full(task))
        | Err(crossbeam_channel::TrySendError::Disconnected(task)) => {
            std::thread::spawn(task);
        }
        _ => {}
    }
}
