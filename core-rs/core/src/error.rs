use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    Link,
    Ipv4,
    Ipv6,
    Tcp,
    Udp,
    Icmp,
    Dns,
}

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Layer::Link => "link",
            Layer::Ipv4 => "ipv4",
            Layer::Ipv6 => "ipv6",
            Layer::Tcp => "tcp",
            Layer::Udp => "udp",
            Layer::Icmp => "icmp",
            Layer::Dns => "dns",
        };
        f.write_str(name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Truncated {
        layer: Layer,
        needed: usize,
        available: usize,
    },
    Malformed {
        layer: Layer,
        reason: &'static str,
    },
}

impl ParseError {
    pub fn layer(&self) -> Layer {
        match self {
            ParseError::Truncated { layer, .. } | ParseError::Malformed { layer, .. } => *layer,
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Truncated {
                layer,
                needed,
                available,
            } => write!(f, "{layer}: truncated, need {needed} bytes, have {available}"),
            ParseError::Malformed { layer, reason } => write!(f, "{layer}: {reason}"),
        }
    }
}

impl std::error::Error for ParseError {}
