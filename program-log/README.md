<p align="center">
  <a href="https://solana.com">
    <img alt="Solana" src="https://github.com/user-attachments/assets/31bfc6b9-fdaa-4f3c-b802-2de70548b943" height="80" />
  </a>
</p>

# `solana-program-log`
<a href="https://crates.io/crates/solana-program-log"><img src="https://img.shields.io/crates/v/solana-program-log?logo=rust" /></a>
<a href="https://docs.rs/solana-program-log"><img src="https://img.shields.io/docsrs/solana-program-log?logo=docsdotrs" /></a>

Currently, logging messages that require formatting are a bit heavy on the CU consumption. There are two aspects when comes to determining the cost of a log message:

1. `base cost`: this is the cost of the log syscall. It will either be the [`syscall_base_cost`](https://github.com/anza-xyz/agave/blob/master/compute-budget/src/compute_budget.rs#L167) (currently `100` CU) or a number of CUs equal to the length of the message, whichever value is higher.

2. `formatting cost`: the compute units required to format the message. This is variable and depends on the number and type of the arguments. Formatting is performed using Rust built-in `format!` routines, which in turn use `format_args!`.

It is known that Rust formatting routines are CPU-intensive for constrained environments. This has been noted on both the `solana-program` [`msg!`](https://docs.rs/solana-program/latest/solana_program/macro.msg.html) documentation and more generally on [rust development](https://github.com/rust-lang/rust/issues/99012).

While the cost related to (1) is *fixed*, in the sense that it does not change with the addition of formatting, it is possible to improve the overall cost of logging a formatted message using a lightweight formatting routine &mdash; this is what this crate does.

This crate defines a lightweight `Logger` type to format log messages and a companion `log!` macro. The logger is a fixed size buffer that can be used to format log messages before sending them to the log output. Any type that implements the `Log` trait can be appended to the logger. Additionally, the logger can the dereferenced to a `&[u8]` slice, which can be used for other purposes &mdash; e.g., it can be used to create `&str` to be stored on an account or return data of programs.

Below is a sample of the improvements observed when formatting log messages, measured in terms of compute units (CU):
| Output message                      | `log!` | `msg!`          | Improvement (%) |
|-------------------------------------|--------|-----------------|-----------------|
| `"Hello world!"`                    | 104    | 104             | -               |
| `"lamports={}"` + `u64`             | 286    | 625 (+339)      | 55%             |
| `"{}"` + `[&str; 2]`                | 119    | 1610 (+1491)    | 93%             |
| `"lamports={}"` + `i64`             | 299    | 659 (+360)      | 55%             |
| `"{}"` + `[u8; 32]` (address bytes) | 2783   | 8397 (+5614)    | 67%             |
| `"lamports={:.9}"` + `u64`          | 438    | 2656 (+2218)`*` | 84%             |

`*` For `msg!`, the value is logged as a `f64` otherwise the precision formatting is ignored.

## Features

* Zero dependencies and `no_std` crate
* Independent of SDK (i.e., works with `pinocchio`, `solana-program` or `anchor`)
* Support for `&str`, unsigned and signed integer types
* `log!` macro to facilitate log message formatting

## Getting Started

From your project folder:
```bash
cargo add solana-program-log
```

## Usage

The `Logger` can be used directly:
```rust
use solana_program_log::Logger;

let mut logger = Logger::<100>::default();
logger.append("Hello ");
logger.append("world!");
logger.log();
```

 or via the `log!` macro:
 ```rust
use solana_program_log::log;

let lamports = 1_000_000_000;
log!("transfer amount: {}", lamports);
// Logs the transfer amount in SOL (lamports with 9 decimal digits)
log!("transfer amount (SOL): {:.9}", lamports);
```

Since the formatting routine does not perform additional allocations, the `Logger` type has a fixed size specified on its creation. When using the `log!` macro, it is also possible to specify the size of the logger buffer:

```rust
use solana_program_log::log;

let lamports = 1_000_000_000;
log!(50, "transfer amount: {}", lamports);
```

It is also possible to dereference the `Logger` into a `&[u8]` slice and use the result for other purposes:
```rust
use solana_program_log::Logger;

let amount = 1_000_000_000;
let mut logger = Logger::<100>::default();
logger.append("Prize ");
logger.append(amount);

let prize_title = core::str::from_utf8(&logger)?;
```

When using the `Logger` directly, it is possible to include a precision formatting for numeric values:
```rust
use solana_program_log::{Attribute, Logger};

let lamports = 1_000_000_000;
let mut logger = Logger::<100>::default();
logger.append("SOL: ");
logger.append_with_args(amount, &[Argument::Precision(9)]);
logger.log();
```

or a formatting string on the `log!` macro:
```rust
use solana_program_log::log;

let lamports = 1_000_000_000;
log!("transfer amount (SOL: {:.9}", lamports);
```

For `&str` types, it is possible to specify a maximum length and a truncation strategy using one of the `Argument::Truncate*` variants:
```rust
use solana_program_log::{Attribute, Logger};

let program_name = "solana-program";
let mut logger = Logger::<100>::default();
logger.append_with_args(program_name, &[Argument::TruncateStart(10)]);
// log message: "...program"
logger.log();

let mut logger = Logger::<100>::default();
logger.append_with_args(program_name, &[Argument::TruncateEnd(10)]);
// log message: "solana-..."
logger.log();
```

or a formatting string on the `log!` macro:
```rust
use solana_program_log::log;

let program_name = "solana-program";
// log message: "...program"
log!("{:<.10}", program_name);
// log message: "solana-..."
log!("{:>.10}", program_name);
```

## Formatting Options

Formatting options are represented by `Attribute` variants and can be passed to the `Logger` when appending messages using `append_with_args`.

| Variant                | Description                                     | Macro Format     |
| ---------------------- | ----------------------------------------------- | ---------------- |
| `Precision(u8)`        | Number of decimal places to display for numbers`*` | "{.*precision*}" |
| `TruncateEnd(usize)`   | Truncate the output at the end when the specified maximum number of characters (size) is exceeded | "{>.*size*}"     |
| `TruncateStart(usize)` | Truncate the output at the start when the specified maximum number of characters (size) is exceeded | "{<.*size*}"     |

`*` The `Precision` adds a decimal formatting to integer numbers. This is useful to log numeric integer amounts that represent values with decimal precision.

## License

The code is licensed under the [Apache License Version 2.0](../LICENSE)
