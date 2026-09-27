//! A semaphore whose size can change while it is in use: the server sets
//! each client's share of the global concurrency, and can pause it.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, watch};

pub struct Limiter {
    sem: Arc<Semaphore>,
    size: Mutex<usize>,
    in_use: Arc<AtomicUsize>,
    paused: watch::Sender<bool>,
}

pub struct Permit {
    _permit: OwnedSemaphorePermit,
    in_use: Arc<AtomicUsize>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.in_use.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Limiter {
    pub fn new(size: usize) -> Arc<Limiter> {
        Arc::new(Limiter {
            sem: Arc::new(Semaphore::new(size)),
            size: Mutex::new(size),
            in_use: Arc::new(AtomicUsize::new(0)),
            paused: watch::channel(false).0,
        })
    }

    pub async fn acquire(&self) -> Permit {
        let mut paused = self.paused.subscribe();
        while *paused.borrow_and_update() {
            if paused.changed().await.is_err() {
                break;
            }
        }
        let permit = self.sem.clone().acquire_owned().await.expect("the limiter's semaphore is never closed");
        self.in_use.fetch_add(1, Ordering::Relaxed);
        Permit { _permit: permit, in_use: self.in_use.clone() }
    }

    /// Change the size.  Shrinking waits for permits to come back before it
    /// takes them out of use.
    pub async fn resize(&self, size: usize) {
        let mut cur = self.size.lock().await;
        if size > *cur {
            self.sem.add_permits(size - *cur);
        } else if size < *cur {
            let excess = (*cur - size) as u32;
            let sem = self.sem.clone();
            tokio::spawn(async move {
                if let Ok(p) = sem.acquire_many_owned(excess).await {
                    p.forget();
                }
            });
        }
        *cur = size;
    }

    pub fn set_paused(&self, paused: bool) {
        self.paused.send_replace(paused);
    }

    pub fn paused(&self) -> bool {
        *self.paused.borrow()
    }

    pub async fn size(&self) -> usize {
        *self.size.lock().await
    }

    pub fn in_use(&self) -> usize {
        self.in_use.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn resize_and_pause() {
        let l = Limiter::new(2);
        let a = l.acquire().await;
        let _b = l.acquire().await;
        assert_eq!(l.in_use(), 2);
        assert!(tokio::time::timeout(Duration::from_millis(50), l.acquire()).await.is_err());
        l.resize(3).await;
        let _c = tokio::time::timeout(Duration::from_millis(50), l.acquire()).await.expect("grown");
        l.resize(1).await;
        drop(a);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(tokio::time::timeout(Duration::from_millis(50), l.acquire()).await.is_err(), "shrunk");
        l.set_paused(true);
        l.resize(10).await;
        assert!(tokio::time::timeout(Duration::from_millis(50), l.acquire()).await.is_err(), "paused");
        l.set_paused(false);
        let _d = tokio::time::timeout(Duration::from_millis(50), l.acquire()).await.expect("resumed");
    }
}
