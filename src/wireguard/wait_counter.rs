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

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread::{JoinHandle, sleep, spawn},
        time::Duration,
    };

    use super::*;

    fn start_wait(wait_counter: Arc<WaitCounter>) -> JoinHandle<()> {
        let wait_thread;
        let wait_thread_started = Arc::new(AtomicBool::new(false));

        {
            let started = wait_thread_started.clone();

            wait_thread = spawn(move || {
                started.swap(true, Ordering::SeqCst);
                wait_counter.wait();
            });
        }

        // wait for thread init

        const THREAD_INIT_UPPER_BOUND: Duration = Duration::from_millis(100);

        sleep(THREAD_INIT_UPPER_BOUND);

        assert!(
            wait_thread_started.load(Ordering::SeqCst),
            "thread hasn't started in {THREAD_INIT_UPPER_BOUND:?} ms"
        );

        wait_thread
    }

    #[test]
    fn test_new() {
        let wait_counter = Arc::new(WaitCounter::new());

        assert_eq!(*wait_counter.get_guard(), 0);

        // test that wait() runs without blocking

        let wait_thread = start_wait(wait_counter.clone());

        assert!(wait_thread.is_finished());
    }

    #[test]
    fn test_increase_decrease() {
        let wait_counter = WaitCounter::new();

        wait_counter.increase();

        assert_eq!(*wait_counter.get_guard(), 1);

        wait_counter.decrease();

        assert_eq!(*wait_counter.get_guard(), 0);

        const N_LOOP: usize = 1000;

        for i in 0..N_LOOP {
            wait_counter.increase();
            assert_eq!(*wait_counter.get_guard(), i + 1);
        }

        for i in (0..N_LOOP).rev() {
            wait_counter.decrease();
            assert_eq!(*wait_counter.get_guard(), i);
        }
    }

    #[test]
    fn test_parallel_increase_decrease() {
        let wait_counter = Arc::new(WaitCounter::new());

        const N_THREADS: usize = 32;

        let mut threads = Vec::with_capacity(N_THREADS);

        for _ in 0..N_THREADS {
            let wait_counter = wait_counter.clone();

            wait_counter.increase();

            threads.push(spawn(move || {
                sleep(Duration::from_millis(10));

                wait_counter.decrease();
            }));

            sleep(Duration::from_millis(10));
        }

        for t in threads {
            t.join().unwrap();
        }

        assert_eq!(*wait_counter.get_guard(), 0);
    }

    #[test]
    fn test_wait() {
        let wait_counter = Arc::new(WaitCounter::new());

        wait_counter.increase();

        // test that wait blocks before decrease is called, and doesn't afterward

        let wait_thread = start_wait(wait_counter.clone());

        assert!(!wait_thread.is_finished());

        wait_counter.decrease();

        // wait for notify
        sleep(Duration::from_millis(100));

        assert!(wait_thread.is_finished());
    }
}
