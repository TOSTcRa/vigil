use std::time::{SystemTime, UNIX_EPOCH};

// returns current utc time as rfc3339 string: "2024-01-15T10:30:00Z"
pub fn now_rfc3339() -> String {
    unix_to_rfc3339(now_unix())
}

// converts unix timestamp to rfc3339
pub fn unix_to_rfc3339(secs: u64) -> String {
    let (y, mo, d, h, mi, s) = unix_to_datetime(secs);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, mi, s)
}

// returns current unix timestamp
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// formats current time for log output: "2024-01-15 10:30:00"
pub fn now_local_fmt() -> String {
    let (y, mo, d, h, mi, s) = unix_to_datetime(now_unix());
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", y, mo, d, h, mi, s)
}

// parses rfc3339 string to unix timestamp
// supports "2024-01-15T10:30:00Z" and "2024-01-15T10:30:00+00:00"
pub fn rfc3339_to_unix(s: &str) -> Result<u64, String> {
    // expected at minimum: "YYYY-MM-DDTHH:MM:SSZ"
    if s.len() < 20 {
        return Err(format!("rfc3339 string too short: {}", s));
    }

    let year: u64 = s[0..4].parse().map_err(|_| format!("bad year in: {}", s))?;
    let month: u64 = s[5..7].parse().map_err(|_| format!("bad month in: {}", s))?;
    let day: u64 = s[8..10].parse().map_err(|_| format!("bad day in: {}", s))?;
    let hour: u64 = s[11..13].parse().map_err(|_| format!("bad hour in: {}", s))?;
    let min: u64 = s[14..16].parse().map_err(|_| format!("bad minute in: {}", s))?;
    let sec: u64 = s[17..19].parse().map_err(|_| format!("bad second in: {}", s))?;

    // only accept utc (Z or +00:00)
    let tz = &s[19..];
    if tz != "Z" && tz != "+00:00" {
        return Err(format!("only utc offsets supported, got: {}", tz));
    }

    datetime_to_unix(year, month, day, hour, min, sec)
}

// converts (year, month, day, hour, min, sec) to unix timestamp
fn datetime_to_unix(y: u64, mo: u64, d: u64, h: u64, mi: u64, s: u64) -> Result<u64, String> {
    if mo < 1 || mo > 12 {
        return Err(format!("month out of range: {}", mo));
    }
    if d < 1 || d > 31 {
        return Err(format!("day out of range: {}", d));
    }

    // count days from epoch (1970-01-01) to start of year y
    let mut days: u64 = 0;
    for yr in 1970..y {
        days += if is_leap(yr) { 366 } else { 365 };
    }

    // add days for full months in the current year
    let mdays = month_days(y);
    for m in 0..(mo as usize - 1) {
        days += mdays[m] as u64;
    }

    // add remaining days (day-1 because day 1 = 0 offset)
    days += d - 1;

    Ok(days * 86400 + h * 3600 + mi * 60 + s)
}

// converts unix seconds to (year, month, day, hour, minute, second)
fn unix_to_datetime(secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let s = secs % 60;
    let mi = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let mut days = secs / 86400;

    // find year
    let mut y = 1970u64;
    loop {
        let dy = if is_leap(y) { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        y += 1;
    }

    // find month and day within year
    let mdays = month_days(y);
    let mut mo = 1u64;
    for (i, &md) in mdays.iter().enumerate() {
        if days < md as u64 {
            mo = i as u64 + 1;
            break;
        }
        days -= md as u64;
    }

    let d = days + 1;
    (y, mo, d, h, mi, s)
}

// returns true if year is a leap year
fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// returns days per month for the given year
fn month_days(y: u64) -> [u8; 12] {
    [31, if is_leap(y) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch() {
        assert_eq!(unix_to_rfc3339(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn test_known_date() {
        // 2024-01-01T00:00:00Z = 1704067200
        assert_eq!(unix_to_rfc3339(1704067200), "2024-01-01T00:00:00Z");
    }

    #[test]
    fn test_known_datetime() {
        // 2024-01-15T10:30:00Z = 1705314600
        assert_eq!(unix_to_rfc3339(1705314600), "2024-01-15T10:30:00Z");
    }

    #[test]
    fn test_leap_year_feb29() {
        // 2024 is a leap year: 2024-02-29T00:00:00Z = 1709164800
        assert_eq!(unix_to_rfc3339(1709164800), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn test_non_leap_century() {
        // 1900 is not a leap year; 2100 won't be either
        assert!(!is_leap(1900));
        assert!(!is_leap(2100));
        assert!(is_leap(2000));
        assert!(is_leap(2024));
    }

    #[test]
    fn test_rfc3339_roundtrip() {
        let ts = 1704067200u64;
        let s = unix_to_rfc3339(ts);
        assert_eq!(rfc3339_to_unix(&s).unwrap(), ts);
    }

    #[test]
    fn test_rfc3339_plus_offset() {
        assert_eq!(rfc3339_to_unix("2024-01-01T00:00:00+00:00").unwrap(), 1704067200);
    }

    #[test]
    fn test_rfc3339_z() {
        assert_eq!(rfc3339_to_unix("2024-01-01T00:00:00Z").unwrap(), 1704067200);
    }
}
