use std::sync::{Condvar, Mutex};

pub struct WaitCounter(Mutex<usize>, Condvar);

impl WaitCounter {
    pub fn wait(&self) {
        let mut nread = self.0.lock().unwrap();
        while *nread > 0 {
            nread = self.1.wait(nread).unwrap();
        }
    }

    pub fn new() -> Self {
        Self(Mutex::new(0), Condvar::new())
    }

    pub fn decrease(&self) {
        let mut nread = self.0.lock().unwrap();
        assert!(*nread > 0);
        *nread -= 1;
        if *nread == 0 {
            self.1.notify_all();
        }
    }

    pub fn increase(&self) {
        *self.0.lock().unwrap() += 1;
    }
}
