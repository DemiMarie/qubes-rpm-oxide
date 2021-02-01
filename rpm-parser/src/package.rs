//! Routines for parsing entire RPM packages
//!
//! An RPM package consists of a lead, signature header, immutable header, and
//! payload.  The payload is an opaque compressed archive.

use crate::{
    header::{ImmutableHeader, SignatureHeader},
    load_immutable, load_signature, read_lead, RPMLead,
};
use std::io::{Read, Result};

/// An RPM package
pub struct RPMPackage {
    pub lead: RPMLead,
    pub signature: SignatureHeader,
    pub immutable: ImmutableHeader,
}

/// Package reading security level.  Each level includes all of the checks of
/// the previous ones.
#[derive(Copy, Clone, Ord, PartialOrd, PartialEq, Eq)]
pub enum SecurityLevel {
    /// Allow any package that is syntactically correct.  This is enough to
    /// ensure that `rpmkeys --define '_pkgverify_level all' --checksig -- "$PKG"`
    /// will catch a malicious package, as it still is enough to protect
    /// `rpmkeys` from exploit attempts.
    InsecureAllowAny,
    /// Require that the package has a header signature and a payload hash, and
    /// that the payload hash is correct.  This is enough to ensure that DNF’s
    /// signature verification will catch a malicious package.
    InsecureRequireHeaderSignatureAndPayloadHashButDoNotCheckSignatures,
    /// Require that the package is validly signed.  This is equivalent to
    /// `rpmkeys --define '_pkgverify_level all' --checksig -- "$PKG"`, but
    /// with a much lower likelyhood of vulnerabilities.
    SecureCheckSignatures,
}

impl RPMPackage {
    /// Load a package from `r`
    pub fn read(r: &mut dyn Read) -> Result<Self> {
        let lead = read_lead(r)?;
        let signature = load_signature(r)?;
        let immutable = load_immutable(r)?;
        Ok(Self {
            lead,
            signature,
            immutable,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_lua_rpm() {
        let mut s: &[u8] = include_bytes!("../../lua-5.4.2-1.fc33.x86_64.rpm");
        let RPMPackage {
            lead: _,
            signature,
            immutable,
        } = RPMPackage::read(&mut s).unwrap();
        let SignatureHeader {
            header: _,
            header_signature,
            header_payload_signature,
        } = signature;
        assert!(header_signature.is_some());
        assert!(header_payload_signature.is_some());
        let ImmutableHeader {
            header: _,
            payload_digest,
            payload_digest_algorithm,
        } = immutable;
        assert_eq!(payload_digest.unwrap().len(), 65);
        assert_eq!(payload_digest_algorithm.unwrap(), 8);
    }
}
