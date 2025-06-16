//! Definitions for the native SOL token and its fractional lamports.

#![allow(clippy::arithmetic_side_effects)]

/// There are 10^9 lamports in one SOL
pub const LAMPORTS_PER_SOL: u64 = 1_000_000_000;
const LAMPORTS_PER_SOL_F64: f64 = LAMPORTS_PER_SOL as f64;
const SOL_DECIMALS: usize = 9;

/// Approximately convert fractional native tokens (lamports) into native tokens (SOL)
#[deprecated(
    since = "2.3.0",
    note = "solana_cli_output::display::build_balance_message"
)]
pub fn lamports_to_sol(lamports: u64) -> f64 {
    lamports as f64 / LAMPORTS_PER_SOL_F64
}

/// Approximately convert native tokens (SOL) into fractional native tokens (lamports)
#[deprecated(since = "2.3.0", note = "sol_str_to_lamports")]
pub fn sol_to_lamports(sol: f64) -> u64 {
    // NaNs return zero, negative values saturate to u64::MIN (i.e. zero), positive values saturate to u64::MAX
    // https://doc.rust-lang.org/reference/expressions/operator-expr.html#r-expr.as.numeric.float-as-int
    (sol * LAMPORTS_PER_SOL_F64).round() as u64
}

/// Convert native tokens (SOL) into fractional native tokens (lamports)
pub fn sol_str_to_lamports(sol_str: &str) -> Option<u64> {
    if sol_str == "." {
        None
    } else {
        let (sol, lamports) = sol_str.split_once('.').unwrap_or((sol_str, ""));
        let sol = if sol.is_empty() {
            0
        } else {
            sol.parse::<u64>().ok()?
        };
        let lamports = if lamports.is_empty() {
            0
        } else {
            format!("{:0<9}", lamports)[..SOL_DECIMALS].parse().ok()?
        };
        LAMPORTS_PER_SOL
            .checked_mul(sol)
            .and_then(|x| x.checked_add(lamports))
    }
}

use std::fmt::{Debug, Display, Formatter, Result};
pub struct Sol(pub u64);

impl Sol {
    fn write_in_sol(&self, f: &mut Formatter) -> Result {
        write!(
            f,
            "◎{}.{:09}",
            self.0 / LAMPORTS_PER_SOL,
            self.0 % LAMPORTS_PER_SOL
        )
    }
}

impl Display for Sol {
    fn fmt(&self, f: &mut Formatter) -> Result {
        self.write_in_sol(f)
    }
}

impl Debug for Sol {
    fn fmt(&self, f: &mut Formatter) -> Result {
        self.write_in_sol(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::excessive_precision)]
    #[allow(deprecated)]
    fn test_lamports_to_sol() {
        assert_eq!(0.0, lamports_to_sol(0));
        assert_eq!(0.000000001, lamports_to_sol(1));
        assert_eq!(0.00000001, lamports_to_sol(10));
        assert_eq!(0.0000001, lamports_to_sol(100));
        assert_eq!(0.000001, lamports_to_sol(1000));
        assert_eq!(0.00001, lamports_to_sol(10000));
        assert_eq!(0.0001, lamports_to_sol(100000));
        assert_eq!(0.001, lamports_to_sol(1000000));
        assert_eq!(0.01, lamports_to_sol(10000000));
        assert_eq!(0.1, lamports_to_sol(100000000));
        assert_eq!(1., lamports_to_sol(1000000000));
        assert_eq!(4.1, lamports_to_sol(4_100_000_000));
        assert_eq!(8.2, lamports_to_sol(8_200_000_000));
        assert_eq!(8.50228288, lamports_to_sol(8_502_282_880));
        assert_eq!(18446744073.70955276489257812500, lamports_to_sol(u64::MAX));
        assert_eq!(
            18446744073.70955276489257812500,
            lamports_to_sol(u64::MAX - 1023)
        );
        assert_eq!(
            18446744073.70954895019531250000,
            lamports_to_sol(u64::MAX - 1024)
        );
        assert_eq!(
            18446744073.70954895019531250000,
            lamports_to_sol(u64::MAX - 5119)
        );
        assert_eq!(
            18446744073.70954513549804687500,
            lamports_to_sol(u64::MAX - 5120)
        );
    }

    #[test]
    #[allow(clippy::excessive_precision)]
    #[allow(deprecated)]
    fn test_sol_to_lamports() {
        assert_eq!(0, sol_to_lamports(0.0));
        assert_eq!(1, sol_to_lamports(0.000000001));
        assert_eq!(10, sol_to_lamports(0.00000001));
        assert_eq!(100, sol_to_lamports(0.0000001));
        assert_eq!(1000, sol_to_lamports(0.000001));
        assert_eq!(10000, sol_to_lamports(0.00001));
        assert_eq!(100000, sol_to_lamports(0.0001));
        assert_eq!(1000000, sol_to_lamports(0.001));
        assert_eq!(10000000, sol_to_lamports(0.01));
        assert_eq!(100000000, sol_to_lamports(0.1));
        assert_eq!(1000000000, sol_to_lamports(1.));
        assert_eq!(4_100_000_000, sol_to_lamports(4.1));
        assert_eq!(8_200_000_000, sol_to_lamports(8.2));
        assert_eq!(8_502_282_880, sol_to_lamports(8.50228288));
        assert_eq!(0, sol_to_lamports(-1.0));
        assert_eq!(0, sol_to_lamports(f64::NEG_INFINITY));
        assert_eq!(0, sol_to_lamports(f64::NAN));
        assert_eq!(u64::MAX, sol_to_lamports(f64::INFINITY));
        assert_eq!(u64::MAX, sol_to_lamports(18446744073.70955276489257812500));
        assert_eq!(
            u64::MAX - 2047,
            sol_to_lamports(18446744073.70954895019531250000)
        );
        assert_eq!(
            u64::MAX - 6143,
            sol_to_lamports(18446744073.70954513549804687500)
        );
    }

    #[test]
    fn test_sol_str_to_lamports() {
        assert_eq!(0, sol_str_to_lamports("0.0").unwrap());
        assert_eq!(1, sol_str_to_lamports("0.000000001").unwrap());
        assert_eq!(10, sol_str_to_lamports("0.00000001").unwrap());
        assert_eq!(100, sol_str_to_lamports("0.0000001").unwrap());
        assert_eq!(1000, sol_str_to_lamports("0.000001").unwrap());
        assert_eq!(10000, sol_str_to_lamports("0.00001").unwrap());
        assert_eq!(100000, sol_str_to_lamports("0.0001").unwrap());
        assert_eq!(1000000, sol_str_to_lamports("0.001").unwrap());
        assert_eq!(10000000, sol_str_to_lamports("0.01").unwrap());
        assert_eq!(100000000, sol_str_to_lamports("0.1").unwrap());
        assert_eq!(1000000000, sol_str_to_lamports("1").unwrap());
        assert_eq!(4_100_000_000, sol_str_to_lamports("4.1").unwrap());
        assert_eq!(8_200_000_000, sol_str_to_lamports("8.2").unwrap());
        assert_eq!(8_502_282_880, sol_str_to_lamports("8.50228288").unwrap());

        assert_eq!(
            u64::MAX,
            sol_str_to_lamports("18446744073.709551615").unwrap()
        );
        // bigger than u64::MAX, error
        assert_eq!(None, sol_str_to_lamports("18446744073.709551616"));
        // Negative, error
        assert_eq!(None, sol_str_to_lamports("-0.000000001"));
        // i64::MIN as string, error
        assert_eq!(None, sol_str_to_lamports("-9223372036.854775808"));
    }
}
