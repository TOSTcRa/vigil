use inotify::{Inotify, WatchDescriptor, WatchMask};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio_stream::StreamExt;

// Real-time game directory watcher using Linux inotify
// Recursively watches all subdirectories for file changes (modify/create/delete/move)
// When a new subdirectory appears, automatically adds a watch on it
// Modified files are hashed and compared against baseline to detect tampering

pub async fn watch_game_dir(dir: String, baseline: HashMap<String, String>) -> std::io::Result<()> {
    let inotify = Inotify::init()?;

    let mut wd_to_path: HashMap<WatchDescriptor, PathBuf> = HashMap::new();

    let mask = WatchMask::MODIFY
        | WatchMask::CREATE
        | WatchMask::DELETE
        | WatchMask::MOVED_FROM
        | WatchMask::MOVED_TO;

    add_watches_recursive(Path::new(&dir), &inotify, mask, &mut wd_to_path)?;

    println!(
        "[INOTIFY] Watching {} ({} directories)",
        dir,
        wd_to_path.len()
    );

    let mut stream = inotify.into_event_stream([0u8; 4096])?;

    while let Some(event_or_err) = stream.next().await {
        let event = match event_or_err {
            Ok(ev) => ev,
            Err(e) => {
                eprintln!("[INOTIFY] Error reading event: {}", e);
                continue;
            }
        };

        let dir_path = match wd_to_path.get(&event.wd) {
            Some(p) => p.clone(),
            None => continue,
        };

        let name = match event.name {
            Some(name) => name.to_string_lossy().to_string(),
            None => continue,
        };

        let full_path = dir_path.join(&name);
        let path_str = full_path.to_string_lossy().to_string();

        if event.mask.contains(inotify::EventMask::ISDIR) {
            if event.mask.contains(inotify::EventMask::CREATE)
                || event.mask.contains(inotify::EventMask::MOVED_TO)
            {
                if let Ok(wd) = stream.watches().add(&full_path, mask) {
                    wd_to_path.insert(wd, full_path.clone());
                    println!("[INOTIFY] New directory watched: {}", path_str);
                }
            }
            continue;
        }

        if event.mask.contains(inotify::EventMask::MODIFY) {
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
                Err(_) => {
                    println!("[INOTIFY] MODIFIED: {} (could not hash)", path_str);
                }
            }
        } else if event.mask.contains(inotify::EventMask::CREATE)
            || event.mask.contains(inotify::EventMask::MOVED_TO)
        {
            println!("[INOTIFY] ADDED: {}", path_str);
        } else if event.mask.contains(inotify::EventMask::DELETE)
            || event.mask.contains(inotify::EventMask::MOVED_FROM)
        {
            println!("[INOTIFY] REMOVED: {}", path_str);
        }
    }

    Ok(())
}

// Recursively adds inotify watches on a directory and all its subdirectories
fn add_watches_recursive(
    dir: &Path,
    inotify: &Inotify,
    mask: WatchMask,
    wd_to_path: &mut HashMap<WatchDescriptor, PathBuf>,
) -> std::io::Result<()> {
    let wd = inotify.watches().add(dir, mask)?;
    wd_to_path.insert(wd, dir.to_path_buf());

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.path().is_dir() {
            add_watches_recursive(&entry.path(), inotify, mask, wd_to_path)?;
        }
    }

    Ok(())
}

// Computes SHA-256 hash of a file for integrity comparison against baseline
fn hash_file(path: &Path) -> std::io::Result<String> {
    let bytes = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(format!("{:x}", hasher.finalize()))
}
