use std::fmt::Debug;
use regex::Error;
use thiserror::Error;

/// Represents the different types of errors that can occur in the application.
///
/// Each variant of `AppError` corresponds to a specific error category
/// and provides an appropriate error message.
#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum AppError {
    #[error("regex error: {0}")]
    RegexError(String),
    #[error("I/O error: {0}")]
    IOError(String),
    #[error("process error: {0}")]
    ProcessError(String),

}


impl From<std::io::Error> for AppError {
    /// Converts a `std::io::Error` into an `AppError`.
    ///
    /// # Returns
    /// A new `AppError` with the `FileError`  and the corresponding error message.
    fn from(value: std::io::Error) -> Self {
        AppError::IOError(value.to_string())
    }
}


impl From<regex::Error> for AppError {
    fn from(value: Error) -> Self {
        AppError::RegexError(value.to_string())
    }
}

impl From<ctrlc::Error> for AppError {
    fn from(value: ctrlc::Error) -> Self {
        AppError::ProcessError(value.to_string())
    }   
}