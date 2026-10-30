//! Error messages that keep their causes.

/// `error` followed by each of its causes, separated by `: `. reqwest's own message leaves the
/// cause out, such as a server certificate signed by an authority this machine does not trust,
/// so this crate's errors carry the whole chain in their message.
pub(crate) fn with_causes(error: &(dyn std::error::Error + 'static)) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}
