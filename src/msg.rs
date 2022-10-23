use bytes::Bytes;
use serde::{Deserialize, Serialize};
use stdcode::StdcodeSerializeExt;
use tap::Tap;
use tmelcrypt::{Ed25519PK, HashVal};
use tmelcrypt::{Ed25519SK, Hashable};

pub trait Message {
    fn chash(&self) -> HashVal;
    fn source(&self) -> Ed25519PK;
    fn signature(&self) -> &[u8];
    fn verify_sig(&self) -> bool {
        self.source().verify(&self.chash(), self.signature())
    }
}

/// Proposal structure
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    pub nonce: u128,
    pub tick: u64,
    pub body: Bytes,
    pub source: Ed25519PK,
    pub signature: Bytes,
}

impl Proposal {
    /// Creates a new proposal.
    pub fn new(nonce: u128, tick: u64, body: Bytes, my_sk: Ed25519SK) -> Self {
        let mut template = Proposal {
            nonce,
            tick,
            body,
            source: my_sk.to_public(),
            signature: Bytes::new(),
        };
        template.signature = my_sk.sign(&template.chash()).into();
        template
    }
}

impl Message for Proposal {
    fn chash(&self) -> HashVal {
        self.clone()
            .tap_mut(|s| s.signature = Bytes::new())
            .stdcode()
            .hash()
    }

    fn source(&self) -> Ed25519PK {
        self.source
    }

    fn signature(&self) -> &[u8] {
        &self.signature
    }
}

/// Vote-soliciting structure
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Solicit {
    pub nonce: u128,
    pub tick: u64,
    pub previous: HashVal,
    pub source: Ed25519PK,
    pub signature: Bytes,
}

impl Solicit {
    /// Creates a new solicit.
    pub fn new(nonce: u128, tick: u64, previous: HashVal, my_sk: Ed25519SK) -> Self {
        let mut template = Self {
            nonce,
            tick,
            previous,
            source: my_sk.to_public(),
            signature: Bytes::new(),
        };
        template.signature = my_sk.sign(&template.chash()).into();
        template
    }
}

impl Message for Solicit {
    fn chash(&self) -> HashVal {
        self.clone()
            .tap_mut(|s| s.signature = Bytes::new())
            .stdcode()
            .hash()
    }

    fn source(&self) -> Ed25519PK {
        self.source
    }

    fn signature(&self) -> &[u8] {
        &self.signature
    }
}

/// A vote.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub nonce: u128,
    pub voting_for: HashVal,
    pub source: Ed25519PK,
    pub signature: Bytes,
}

impl Vote {
    /// Creates a new vote.
    pub fn new(nonce: u128, voting_for: HashVal, my_sk: Ed25519SK) -> Self {
        let mut template = Vote {
            nonce,
            voting_for,
            source: my_sk.to_public(),
            signature: Bytes::new(),
        };
        template.signature = my_sk.sign(&template.chash()).into();
        template
    }
}

impl Message for Vote {
    fn chash(&self) -> HashVal {
        self.clone()
            .tap_mut(|s| s.signature = Bytes::new())
            .stdcode()
            .hash()
    }

    fn source(&self) -> Ed25519PK {
        self.source
    }

    fn signature(&self) -> &[u8] {
        &self.signature
    }
}
