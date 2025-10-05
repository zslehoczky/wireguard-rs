use std::sync::{Condvar, Mutex, MutexGuard};

pub struct WaitCounter(Mutex<usize>, Condvar);

impl WaitCounter {
    pub fn wait(&self) {
        let mut nread = self.get_guard();
        while *nread > 0 {
            nread = self.1.wait(nread).unwrap();
        }
    }

    pub fn new() -> Self {
        Self(Mutex::new(0), Condvar::new())
    }

    pub fn decrease(&self) {
        let mut nread = self.get_guard();
        assert!(*nread > 0);
        *nread -= 1;
        if *nread == 0 {
            self.1.notify_all();
        }
    }

    pub fn increase(&self) {
        *self.get_guard() += 1;
    }

    fn get_guard(&self) -> MutexGuard<'_, usize> {
        self.0.lock().unwrap()
    }
}
