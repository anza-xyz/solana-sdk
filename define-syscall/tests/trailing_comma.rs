use solana_define_syscall::define_syscall;

// Regression test for #701: argument lists should accept an optional trailing comma.
define_syscall!(fn syscall_with_ret(a: u64, b: *const u8,) -> u64);
define_syscall!(fn syscall_without_ret(a: u64,));

#[test]
fn define_syscall_accepts_trailing_comma() {}
