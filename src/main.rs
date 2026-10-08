fn main() {
    // A shell bootstrap may start us as a background child with SIGINT ignored;
    // restore default cancellation before anything installs its own handlers.
    onebox::sys::signal::reset_interrupt_disposition();
    let code = match onebox::cli::run(std::env::args_os().skip(1).collect()) {
        Ok(()) => 0,
        Err(error) => onebox::error::report(&error),
    };
    std::process::exit(code);
}
