fn main() {
    // A shell bootstrap runs us as a background child to forward signals and
    // clean its download directory; POSIX shells may inherit SIGINT=ignored.
    // Restore normal cancellation before any module installs its own handler.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
    }
    if let Err(error) = onebox::cli::run() {
        if error
            .downcast_ref::<onebox::ExitError>()
            .is_some_and(|e| e.code == 0)
        {
            println!("{error}");
            return;
        }
        eprintln!("[错误] {error}");
        let code = error
            .downcast_ref::<onebox::ExitError>()
            .map(|e| e.code)
            .unwrap_or_else(|| {
                if error.downcast_ref::<onebox::ui::Cancelled>().is_some() {
                    130
                } else {
                    1
                }
            });
        std::process::exit(code);
    }
}
