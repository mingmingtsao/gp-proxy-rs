//! Independent implementation of the documented GlobalProtect TLS wire format.
//! No host interface, route, resolver or firewall configuration happens here.

mod bootstrap;
mod challenge;
mod client;
mod config;
mod form;
mod frame;
mod portal;
mod secret_buffer;

pub use challenge::{LoginChallenge, LoginProgress};
pub use client::{parse_login, GatewayClient, HipStatus, ResumptionPolicy, Session, TlsTunnel};
pub use config::{parse_config, GatewayDomainRule, TunnelConfig};
pub use frame::{read_frame, write_frame, Frame};
pub use portal::{PortalChallenge, PortalClient, PortalCookies, PortalProgress};

#[derive(Debug, thiserror::Error)]
pub enum GpError {
    #[error("GlobalProtect I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("GlobalProtect operation timed out")]
    Timeout,
    #[error("GlobalProtect operation cancelled before credential submission")]
    Cancelled,
    #[error("GlobalProtect protocol error: {0}")]
    Protocol(&'static str),
    #[error("gateway rejected authentication or the session expired")]
    Authentication,
    #[error("gateway refused tunnel configuration (session or client parameters rejected)")]
    ConfigurationRejected,
    #[error("gateway requires an unsupported authentication flow or interactive authentication is disabled")]
    UnsupportedAuthentication,
    #[error("gateway returned HTTP status {0}")]
    HttpStatus(u16),
}

pub(crate) const MAX_XML: usize = 1024 * 1024;

pub(crate) fn xml(input: &str) -> Result<roxmltree::Document<'_>, GpError> {
    if input.len() > MAX_XML {
        return Err(GpError::Protocol("XML response exceeds limit"));
    }
    roxmltree::Document::parse_with_options(
        input,
        roxmltree::ParsingOptions {
            allow_dtd: false,
            nodes_limit: 20_000,
            ..Default::default()
        },
    )
    .map_err(|error| {
        // Never format the parser error itself: some variants contain text
        // copied from the gateway, potentially including credentials or keys.
        let kind = match error {
            roxmltree::Error::DtdDetected => "dtd",
            roxmltree::Error::UnknownEntityReference(..) => "unknown_entity",
            roxmltree::Error::MalformedEntityReference(..) => "malformed_entity",
            roxmltree::Error::NonXmlChar(..) => "non_xml_character",
            roxmltree::Error::UnexpectedDeclaration(..) => "declaration_position",
            roxmltree::Error::UnexpectedCloseTag(..) => "unmatched_close_tag",
            roxmltree::Error::UnexpectedEndOfStream => "truncated",
            roxmltree::Error::NodesLimitReached => "node_limit",
            roxmltree::Error::UnknownToken(..) => "unknown_token",
            _ => "malformed_xml",
        };
        tracing::warn!(
            kind,
            row = error.pos().row,
            column = error.pos().col,
            bytes = input.len(),
            starts_with_markup = input.trim_start().starts_with('<'),
            "gateway XML rejected (contents redacted)"
        );
        GpError::Protocol("invalid XML response")
    })
}

/// Scalar protocol fields cannot hide a second interpretation after a child
/// element or a comment splitting text. Empty login arguments remain valid.
pub(crate) fn scalar_text<'a>(node: roxmltree::Node<'a, 'a>) -> Result<&'a str, GpError> {
    if node.children().any(|child| child.is_element())
        || node.children().filter(|child| child.is_text()).count() > 1
    {
        return Err(GpError::Protocol("ambiguous scalar XML content"));
    }
    Ok(node.text().unwrap_or(""))
}

pub(crate) fn child_text<'a>(
    node: roxmltree::Node<'a, 'a>,
    name: &str,
) -> Result<Option<&'a str>, GpError> {
    let mut children = node.children().filter(|child| child.has_tag_name(name));
    let first = children.next();
    if children.next().is_some() {
        return Err(GpError::Protocol("duplicate scalar XML field"));
    }
    first
        .map(|child| scalar_text(child).map(str::trim))
        .transpose()
        .map(|value| value.filter(|value| !value.is_empty() && *value != "(null)"))
}
