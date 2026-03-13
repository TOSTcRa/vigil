use std::collections::HashMap;
use std::path::{Path, PathBuf};

// inotify event flags
const IN_MODIFY: u32 = 0x00000002;
const IN_CREATE: u32 = 0x00000100;
const IN_DELETE: u32 = 0x00000200;
const IN_MOVED_FROM: u32 = 0x00000040;
const IN_MOVED_TO: u32 = 0x00000080;
const IN_ISDIR: u32 = 0x40000000;
const IN_CLOEXEC: i32 = 0o2000000;

unsafe extern "C" {
    fn inotify_init1(flags: i32) -> i32;
    fn inotify_add_watch(fd: i32, pathname: *const u8, mask: u32) -> i32;
    fn read(fd: i32, buf: *mut u8, count: usize) -> isize;
    fn close(fd: i32) -> i32;
}

// kernel inotify_event layout (name field follows immediately after)
#[repr(C)]
struct InotifyEvent {
    wd: i32,
    mask: u32,
    cookie: u32,
    len: u32,
}

// watches a game directory for file changes, comparing modified files against baseline hashes
// runs in a blocking loop - meant to be called from std::thread::spawn
pub fn watch_game_dir(dir: String, baseline: HashMap<String, String>) -> Result<(), String> {
    let fd = unsafe { inotify_init1(IN_CLOEXEC) };
    if fd < 0 {
        return Err("inotify_init failed".to_string());
    }

    let mut wd_to_path: HashMap<i32, PathBuf> = HashMap::new();
    let mask = IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO;

    add_watches_recursive(fd, Path::new(&dir), mask, &mut wd_to_path)?;

    println!("[INOTIFY] Watching {} ({} directories)", dir, wd_to_path.len());

    let mut buf = vec![0u8; 4096];
    loop {
        let n = unsafe { read(fd, buf.as_mut_ptr(), buf.len()) };
        if n <= 0 {
            break;
        }

        let mut offset = 0;
        while offset < n as usize {
            let event = unsafe { &*(buf.as_ptr().add(offset) as *const InotifyEvent) };
            let name_len = event.len as usize;

            let name = if name_len > 0 {
                let name_ptr = unsafe { buf.as_ptr().add(offset + std::mem::size_of::<InotifyEvent>()) };
                let name_bytes = unsafe { std::slice::from_raw_parts(name_ptr, name_len) };
                let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_len);
                String::from_utf8_lossy(&name_bytes[..end]).to_string()
            } else {
                offset += std::mem::size_of::<InotifyEvent>();
                continue;
            };

            offset += std::mem::size_of::<InotifyEvent>() + name_len;

            let dir_path = match wd_to_path.get(&event.wd) {
                Some(p) => p.clone(),
                None => continue,
            };

            let full_path = dir_path.join(&name);
            let path_str = full_path.to_string_lossy().to_string();

            if event.mask & IN_ISDIR != 0 {
                if event.mask & (IN_CREATE | IN_MOVED_TO) != 0 {
                    add_watch(fd, &full_path, mask, &mut wd_to_path);
                    println!("[INOTIFY] New directory watched: {}", path_str);
                }
                continue;
            }

            if event.mask & IN_MODIFY != 0 {
                match hash_file(&full_path) {
                    Ok(hash) => {
                        if let Some(baseline_hash) = baseline.get(&path_str) {
                            if *baseline_hash != hash {
                                println!("[INOTIFY] MODIFIED: {} (hash changed)", path_str);
                            }
                        } else {
                            println!("[INOTIFY] MODIFIED: {} (not in baseline)", path_str);
                        }
                    }
                    Err(_) => println!("[INOTIFY] MODIFIED: {} (could not hash)", path_str),
                }
            } else if event.mask & (IN_CREATE | IN_MOVED_TO) != 0 {
                println!("[INOTIFY] ADDED: {}", path_str);
            } else if event.mask & (IN_DELETE | IN_MOVED_FROM) != 0 {
                println!("[INOTIFY] REMOVED: {}", path_str);
            }
        }
    }

    unsafe { close(fd) };
    Ok(())
}

fn add_watch(fd: i32, path: &Path, mask: u32, wd_to_path: &mut HashMap<i32, PathBuf>) {
    let path_str = format!("{}\0", path.display());
    let wd = unsafe { inotify_add_watch(fd, path_str.as_ptr(), mask) };
    if wd >= 0 {
        wd_to_path.insert(wd, path.to_path_buf());
    }
}

fn add_watches_recursive(
    fd: i32,
    dir: &Path,
    mask: u32,
    wd_to_path: &mut HashMap<i32, PathBuf>,
) -> Result<(), String> {
    add_watch(fd, dir, mask, wd_to_path);
    for entry in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.path().is_dir() {
            add_watches_recursive(fd, &entry.path(), mask, wd_to_path)?;
        }
    }
    Ok(())
}

fn hash_file(path: &Path) -> std::io::Result<String> {
    let bytes = std::fs::read(path)?;
    Ok(crate::crypto::sha256_hex(&bytes))
}
