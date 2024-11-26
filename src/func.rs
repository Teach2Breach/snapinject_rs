use Snapshotting_rs::ProcessSnapshot;
use winapi::um::winnt::HANDLE;

pub fn capture_process_snapshot(handle: HANDLE) -> Result<(), String> {
    println!("Capturing process...");
    match ProcessSnapshot::new(handle) {
        Ok(snap) => {
            println!("Process snapshot completed successfully");
            println!("Snapshot handle: {:?}", snap);
            println!("Snapshot will be automatically freed when it goes out of scope");
            Ok(())
        },
        Err(e) => Err(format!("Error capturing process snapshot: {}", e))
    }
}