use std::collections::HashMap;

use bytes::Bytes;
use tmelcrypt::{Ed25519PK, HashVal};

/// Proposal structure
pub struct Proposal {
    nonce: u128,
    body: Bytes,
    source: Ed25519PK,
    signature: Bytes,
}

/// Vote-soliciting structure
pub struct VoteSolicit {
    nonce: u128,
    previous: HashVal,
    source: Ed25519PK,
    signature: Bytes,
}

/// A vote.
pub struct Vote {
    nonce: u128,
    voting_for: HashVal,
    source: Ed25519PK,
    signature: Bytes,
}

/// Core consensus logic. Stores the tree, etc.
pub struct Core {
    valid_proposals: HashMap<HashVal, Bytes>,
    vote_solicits: HashMap<HashVal, VoteSolicit>,
    votes: HashMap<HashVal, Vote>,
}
