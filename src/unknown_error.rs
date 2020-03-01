use serde::Deserialize;
use std::fmt;

/// A struct to deserialize the errors returned from AWS
/// ```<Response><Errors><Error><Code>InvalidPermission.Duplicate</Code><Message>the specified rule "peer: 86.146.196.106/32, TCP, from port: 22, to port: 22, ALLOW" already exists</Message></Error></Errors><RequestID>9c6e08c8-99ad-447e-9af6-d64ffdbe076a</RequestID></Response>```
#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename = "Response")]
pub struct UnknownError {
    #[serde(rename = "Errors")]
    pub errors: Errors,
}

impl fmt::Display for UnknownError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.errors
                .errors
                .iter()
                .map(|e| e.message.as_str())
                .collect::<Vec<&str>>()
                .join("\n")
        )
    }
}

// Additional intermediatary struct required: see https://github.com/tafia/quick-xml/issues/175
#[derive(Debug, Deserialize, PartialEq)]
pub struct Errors {
    #[serde(rename = "Error")]
    errors: Vec<Error>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct Error {
    pub message: String,
}
