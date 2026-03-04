// extracts socket inode numbers from /proc/PID/fd
// each fd entry is a symlink — if it points to "socket:[12345]" thats a network socket
// inode number is used to match against /proc/net/tcp to find actual connections
// returns vec of inode numbers for this process
pub fn get_inode(pid: u64) -> std::io::Result<Vec<u64>> {
    let path = format!("/proc/{}/fd", pid);
    let dir = std::fs::read_dir(path)?;
    let mut res: Vec<u64> = vec![];
    for entry in dir {
        let entry = entry?;
        let content = std::fs::read_link(entry.path())?;
        let symlink = content.to_string_lossy();

        if symlink.starts_with("socket:[") {
            let item = symlink.trim_start_matches("socket:[").trim_end_matches("]");
            if item.is_empty() {
                continue;
            }

            if let Ok(num) = item.parse::<u64>() {
                res.push(num);
            }
        }
    }
    Ok(res)
}

// matches socket inodes against /proc/net/tcp to find active TCP connections
// /proc/net/tcp format: sl local_addr remote_addr st ... inode
// remote_addr is hex encoded — e.g. "0100007F:1F90" = 127.0.0.1:8080
// skips header line (starts with "sl") and connections with no remote (00000000:0000)
// ip bytes are in little-endian order in /proc/net/tcp, converted to readable dotted format
// returns vec of "ip:port" strings for matched inodes
pub fn get_connections(inodes: &[u64]) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut res: Vec<String> = vec![];
    let path = "/proc/net/tcp";
    let content = std::fs::read_to_string(path)?;
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts[0] == "sl" {
            continue;
        }
        if parts[2] == "00000000:0000" {
            continue;
        }
        let line_inode = parts[9].parse::<u64>()?;
        if inodes.contains(&line_inode) {
            let addr_parts: Vec<&str> = parts[2].split(":").collect();
            let ip_be = u32::from_str_radix(addr_parts[0], 16)?;
            let ip_arr = ip_be.to_be_bytes();
            let ip = format!("{}.{}.{}.{}", ip_arr[0], ip_arr[1], ip_arr[2], ip_arr[3]);
            let port = u16::from_str_radix(addr_parts[1], 16)?;
            res.push(format!("{}:{}", ip, port));
        }
    }

    Ok(res)
}
