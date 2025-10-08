<p align="center">
  <a href="https://solana.com">
    <img alt="Solana" src="https://github.com/user-attachments/assets/31bfc6b9-fdaa-4f3c-b802-2de70548b943" height="80" />
  </a>
</p>

# `solana-program-log-macro`
<a href="https://crates.io/crates/solana-program-log-macro"><img src="https://img.shields.io/crates/v/solana-program-log-macro?logo=rust" /></a>


Companion <code>log!</code> macro for <a href="https://crates.io/crates/solana-program-log"><code>solana-program-log</code></a>. The macro automates the creation of a `Logger` object to log a message and supports a subset of the [`format!`](https://doc.rust-lang.org/std/fmt/) syntax. The format string is parsed at compile time and generates the calls to a `Logger` object to with the corresponding formatted message.

There is also a helper <code>log_cu_usage!</code> macro which can be used to instrument functions with compute unit logging.

## Usage

### `log!`

The macro works very similar to `solana-program` [`msg!`](https://docs.rs/solana-msg/3.0.0/solana_msg/macro.msg.html) macro.

To output a simple message (static `&str`):
```rust
use solana_program_log::log;

log!("a simple log");
```

To output a formatted message:
```rust
use solana_program_log::log;

let amount = 1_000_000_000;
log!("transfer amount: {}", amount);
```

Since a `Logger` size is statically determined, messages are limited to `200` length by default. When logging larger messages, it is possible to increase the logger buffer size:
```rust
use solana_program_log::log;

let very_long_message = "...";
log!(500, "message: {}", very_long_message);
```

It is possible to include a precision formatting for numeric values:
```rust
use solana_program_log::log;

let lamports = 1_000_000_000;
log!("transfer amount (SOL: {:.9}", lamports);
```

For `&str` types, it is possible to specify a maximum length and a truncation strategy:
```rust
use solana_program_log::log;

let program_name = "solana-program";
// log message: "...program"
log!("{:<.10}", program_name);
// log message: "solana-..."
log!("{:>.10}", program_name);
```

### `log_cu_usage!`

This macro wraps the decorated function with additional logging statements that print the function name and the number of compute units used before and after the function execution.

```rust
#[solana_program_log::log_cu_usage]
fn my_function() {
   // Function body
}
```

The generated output will be:
```
Program log: Function `my_function` consumed 36 compute units
```

## License

The code is licensed under the [Apache License Version 2.0](../LICENSE)
