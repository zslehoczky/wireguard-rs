#[cfg(feature = "profiler")]
use cpuprofiler::PROFILER;

#[cfg(not(feature = "profiler"))]
pub fn profiler_start(_name: &str) {}

#[cfg(feature = "profiler")]
pub fn profiler_start(name: &str) {
    use std::path::Path;

    // find first available path to save profiler output
    let mut n = 0;
    loop {
        let path = format!("./{}-{}.profile", name, n);
        if !Path::new(path.as_str()).exists() {
            println!("Starting profiler: {}", path);
            PROFILER.lock().unwrap().start(path).unwrap();
            break;
        };
        n += 1;
    }
}

#[cfg(not(feature = "profiler"))]
pub fn profiler_stop() {}

#[cfg(feature = "profiler")]
pub fn profiler_stop() {
    println!("Stopping profiler");
    PROFILER.lock().unwrap().stop().unwrap();
}
