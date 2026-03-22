pub fn normalize_tty_name(tty: &str) -> String {
    let name = tty.strip_prefix("/dev/").unwrap_or(tty);
    if let Some(rest) = name.strip_prefix("pts/") {
        format!("pts{rest}")
    } else {
        name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_tty_name_drops_dev_prefix_and_pts_slash() {
        assert_eq!(normalize_tty_name("/dev/pts/3"), "pts3");
        assert_eq!(normalize_tty_name("/dev/tty1"), "tty1");
    }

    #[test]
    fn normalize_tty_name_handles_already_normalized() {
        assert_eq!(normalize_tty_name("pts2"), "pts2");
        assert_eq!(normalize_tty_name("tty0"), "tty0");
    }
}
