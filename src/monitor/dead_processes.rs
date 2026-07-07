use crossbeam::channel::{Receiver, Sender};
use kqueue::{EventData, EventFilter, FilterFlag, Ident, Proc};
use rustix::process::Pid;
use std::collections::VecDeque;
use std::io::{self, PipeReader, PipeWriter};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::{
    collections::HashMap,
    sync::atomic::{AtomicBool, Ordering},
};

/// A watcher that tracks PIDs and check whether it is dead.
pub(crate) struct DeadProcTracker {
    // The sender for sending messages to the watch thread.
    sender: Option<Sender<WatchRequest>>,
    // The owned pipe fd for signaling the watch thread to either receive a message or stop,
    // depending on the status of the sender.
    watch_signal_fd: PipeWriter,
    // The thread housing the queue.
    watch_thread: Option<JoinHandle<Result<(), io::Error>>>,
}

impl Drop for DeadProcTracker {
    fn drop(&mut self) {
        drop(self.sender.take());
        if let Ok(_) = rustix::io::write(&self.watch_signal_fd, &[1])
            && let Some(thread) = self.watch_thread.take()
        {
            let _ = thread.join();
        };
    }
}

impl DeadProcTracker {
    pub(crate) fn build() -> Result<Self, io::Error> {
        let (tx, rx) = crossbeam::channel::unbounded();
        let (watch_signal, watch_signal_writer) = std::io::pipe()?;
        let watch_thread = std::thread::spawn(move || watch_thread(rx, watch_signal));
        Ok(Self {
            sender: Some(tx),
            watch_signal_fd: watch_signal_writer,
            watch_thread: Some(watch_thread),
        })
    }

    pub(crate) fn send_item(&self, item: WatchItem) -> Result<(), io::Error> {
        let sender = self
            .sender
            .as_ref()
            .expect("dead process tracker sender should be available");
        let (ack_tx, ack_rx) = crossbeam::channel::bounded(1);
        let request = WatchRequest { item, ack: ack_tx };
        sender.send(request).map_err(|e| {
            e.into_inner().item.notify_dead();
            io::Error::other("dead process tracker sender channel hung up")
        })?;
        rustix::io::write(&self.watch_signal_fd, &[1]).map_err(|_| {
            io::Error::other("failed to write to watch signal fd to signal the watch thread")
        })?;
        ack_rx
            .recv()
            .map_err(|_| io::Error::other("dead process tracker ack channel hung up"))??;
        Ok(())
    }
}

struct WatchRequest {
    pub(crate) item: WatchItem,
    pub(crate) ack: Sender<Result<(), io::Error>>,
}

pub(crate) struct WatchItem {
    pub(crate) pid: Pid,
    pub(crate) live_flag: Arc<AtomicBool>,
    pub(crate) notify: Sender<()>,
}

impl WatchItem {
    fn notify_dead(self) {
        self.live_flag.store(false, Ordering::Release);
        let _ = self.notify.send(());
    }
}

struct WatchList {
    inner: HashMap<Pid, VecDeque<WatchItem>>,
}

impl WatchList {
    fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    fn notify_process(&mut self, pid: Pid) {
        let items = self.inner.remove(&pid);
        if let Some(items) = items {
            for item in items {
                item.notify_dead();
            }
        }
    }

    fn contains_pid(&self, pid: Pid) -> bool {
        self.inner.get(&pid).is_some_and(|items| !items.is_empty())
    }

    fn track_pid(&mut self, item: WatchItem) {
        self.inner
            .entry(item.pid)
            .or_default()
            .push_back(item);
    }
}

fn watch_thread(receiver: Receiver<WatchRequest>, signal_fd: PipeReader) -> Result<(), io::Error> {
    let mut watcher = kqueue::Watcher::new()?;
    let mut watch_list = WatchList::new();
    // Register signals
    watcher.add_fd(
        signal_fd.as_raw_fd(),
        EventFilter::EVFILT_READ,
        FilterFlag::empty(),
    )?;
    watcher.watch()?;
    let mut requests = VecDeque::new();
    'main_loop: loop {
        // Batch receive all requests
        match receiver.try_recv() {
            Ok(request) => requests.push_back(request),
            Err(crossbeam::channel::TryRecvError::Empty) => {}
            Err(crossbeam::channel::TryRecvError::Disconnected) => {
                return Ok(());
            }
        };
        requests.extend(receiver.try_iter());
        // Process requests one-by-one
        while let Some(request) = requests.pop_front() {
            match watcher.add_pid(
                request.item.pid.as_raw_pid(),
                EventFilter::EVFILT_PROC,
                FilterFlag::NOTE_EXIT,
            ) {
                Ok(_) => {}
                Err(e) => {
                    request.item.notify_dead();
                    let _ = request.ack.send(Err(e));
                    continue;
                }
            }
            // Need to check if watcher.watch() succeeded to perform a rollback
            match watcher.watch() {
                Ok(_) => {}
                Err(e) => {
                    // Remove the process from the watcher if it does not already exist in the watch list.
                    if !watch_list.contains_pid(request.item.pid) {
                        let _ = watcher
                            .remove_pid(request.item.pid.as_raw_pid(), EventFilter::EVFILT_PROC);
                    };
                    request.item.notify_dead();
                    let _ = request.ack.send(Err(e));
                    continue;
                }
            }
            watch_list.track_pid(request.item);
            let _ = request.ack.send(Ok(()));
        }
        // Monitoring block
        loop {
            let event = watcher
                .poll_forever(None)
                .ok_or_else(|| io::Error::other("watcher poll failed"))?;
            match (event.ident, event.data) {
                // Need to add processes
                (Ident::Fd(fd), EventData::ReadReady(bytes)) if fd == signal_fd.as_raw_fd() => {
                    let mut bytes_remaining = bytes;
                    let mut stack_buffer = [0; 4096];
                    while bytes_remaining > 0 {
                        let n = rustix::io::read(&signal_fd, &mut stack_buffer[..bytes_remaining])?;
                        bytes_remaining -= n;
                    }
                    continue 'main_loop;
                }
                (Ident::Pid(pid), EventData::Proc(Proc::Exit(..))) => {
                    let pid = match Pid::from_raw(pid) {
                        Some(pid) => pid,
                        None => continue,
                    };
                    let _ = watcher.remove_pid(pid.as_raw_pid(), EventFilter::EVFILT_PROC);
                    watch_list.notify_process(pid);
                }
                _ => {
                    return Err(io::Error::other("unexpected event"));
                }
            }
        }
    }
}
