use std::collections::{HashMap, HashSet};

use bytes::Bytes;
use itertools::Itertools;
use tmelcrypt::{Ed25519PK, Ed25519SK, HashVal};

use crate::msg::{Message, Proposal, Solicit, Vote};

/// Core consensus logic. Stores the tree, etc.
pub struct Core {
    valid_proposals: HashMap<HashVal, Proposal>,
    vote_solicits: HashMap<HashVal, Solicit>,
    votes: HashMap<HashVal, Vote>,
    tick_source: HashSet<(u64, Ed25519PK)>,
    nonce: u128,

    tick_to_leader: Box<dyn Fn(u64) -> Ed25519PK + Send + Sync + 'static>,
    vote_map: HashMap<Ed25519PK, u64>,
    total_votes: u64,
}

impl Core {
    /// Create a new Core with the given logic.
    pub fn new(
        nonce: u128,
        player_votes: impl IntoIterator<Item = (Ed25519PK, u64)>,
        tick_to_leader: impl Fn(u64) -> Ed25519PK + Send + Sync + 'static,
    ) -> Self {
        let vote_map = player_votes.into_iter().collect::<HashMap<_, _>>();
        let total_votes = vote_map.values().copied().sum();
        Core {
            valid_proposals: Default::default(),
            vote_solicits: Default::default(),
            votes: Default::default(),
            tick_source: Default::default(),
            nonce,
            tick_to_leader: Box::new(tick_to_leader),
            vote_map,
            total_votes,
        }
    }

    /// Insert *my* votes into the tree. We vote for everything that extends from a longest notarized chain; there cannot be duplicates within an epoch because of the tick_source thing.
    pub fn insert_my_votes(&mut self, my_sk: Ed25519SK) {
        let tips: HashSet<HashVal> = self.get_lnc_tips().into_iter().collect();
        if tips.is_empty() {
            // we vote for all the proposals --- they must all be valid to vote for due to checks when adding them
            for prop in self.valid_proposals.keys().copied().collect_vec() {
                let vote = Vote::new(self.nonce, prop, my_sk);
                self.insert_vote(vote)
                    .expect("own vote for a proposal could not be inserted");
            }
        } else {
            // we vote for every solicit that *points to* the tip of a LNC.
            let mut to_insert = vec![];
            for (hash, solicit) in self.vote_solicits.iter() {
                if tips.contains(&solicit.previous) {
                    to_insert.push(Vote::new(self.nonce, *hash, my_sk));
                }
            }
            for vote in to_insert {
                self.insert_vote(vote)
                    .expect("own vote for a solicit could not be inserted")
            }
        }
    }

    /// Insert *my* proposal or solicit. If it's not my turn, literally do nothing.
    pub fn insert_my_prop_or_solicit(
        &mut self,
        tick: u64,
        my_sk: Ed25519SK,
        gen_prop: impl FnOnce() -> Bytes,
    ) {
        if (self.tick_to_leader)(tick) != my_sk.to_public() {
            return; // not my turn
        }
        let tips = self.get_lnc_tips();
        if let Some(&tip) = tips.first() {
            // we arbitrarily picked a longest-notarized-chain tip. send a solicit extending from it.
            let solicit = Solicit::new(self.nonce, tick, tip, my_sk);
            self.insert_solicit(solicit)
                .expect("could not insert my OWN solicit!");
        } else {
            // shoot, we need to insert a proposal
            let proposal = gen_prop();
            let proposal = Proposal::new(self.nonce, tick, proposal, my_sk);
            self.insert_proposal(proposal)
                .expect("could not insert my OWN proposal!");
        }
    }

    /// Obtains the finalized proposal, if such a proposal exists.
    pub fn get_finalized(&self) -> Option<&Proposal> {
        // tips are solicits that do not have any other solicits pointing to them
        let lnc = self.get_lnc_tips();
        let notarized_tips = self
            .vote_solicits
            .keys()
            .filter(|hash| lnc.contains(hash))
            .copied();
        for tip in notarized_tips {
            // we go all the way back to a proposal, checking whether we see *three consecutive tick numbers*.
            let mut tick_numbers = vec![self.vote_solicits[&tip].tick];
            let mut tip_ptr = tip;
            let tr;
            loop {
                if let Some(solicit) = self.vote_solicits.get(&tip_ptr) {
                    tick_numbers.push(solicit.tick);
                    tip_ptr = solicit.previous;
                } else if let Some(prop) = self.valid_proposals.get(&tip_ptr) {
                    tick_numbers.push(prop.tick);
                    tr = prop;
                    break;
                } else {
                    panic!("string of vote solicits that dangle at the end?!?!?!")
                }
            }
            let mut this_is_it = false;
            for window in tick_numbers.windows(3) {
                // DESCENDING ticks
                if window[0] == window[1] + 1 && window[1] == window[2] + 1 {
                    this_is_it = true;
                    break;
                }
            }
            if this_is_it {
                return Some(tr);
            }
        }
        None
    }

    /// Obtains the tips of the longest notarized chain(s).
    pub fn get_lnc_tips(&self) -> Vec<HashVal> {
        let mut memo = HashMap::new();
        let mut hash_and_len = self
            .valid_proposals
            .keys()
            .chain(self.vote_solicits.keys())
            .filter(|hash| self.is_notarized(**hash))
            .map(|h| (*h, self.lookup_len(*h, &mut memo)))
            .collect_vec();
        hash_and_len.sort_unstable_by_key(|a| a.1);
        hash_and_len.reverse();
        let longest_len = hash_and_len.first().map(|s| s.1);
        hash_and_len
            .into_iter()
            .take_while(|s| Some(s.1) == longest_len)
            .map(|s| s.0)
            .sorted()
            .collect_vec()
    }

    /// Insert a proposal.
    pub fn insert_proposal(&mut self, prop: Proposal) -> anyhow::Result<()> {
        if !prop.verify_sig() && (self.tick_to_leader)(prop.tick) == prop.source {
            anyhow::bail!("bad signature")
        }
        if prop.nonce != self.nonce {
            anyhow::bail!("bad nonce")
        }
        if !self.tick_source.insert((prop.tick, prop.source)) {
            anyhow::bail!("this player already sent something for this tick")
        }
        // Now we insert this into the system
        self.valid_proposals.insert(prop.chash(), prop);
        Ok(())
    }

    /// Insert a vote.
    pub fn insert_vote(&mut self, vote: Vote) -> anyhow::Result<()> {
        if !vote.verify_sig() {
            anyhow::bail!("bad signature")
        }
        if vote.nonce != self.nonce {
            anyhow::bail!("bad nonce")
        }
        // check that this  vote actually votes for something
        if !self.vote_solicits.contains_key(&vote.voting_for)
            && !self.valid_proposals.contains_key(&vote.voting_for)
        {
            anyhow::bail!("vote not voting for anything")
        }
        self.votes.insert(vote.chash(), vote);
        Ok(())
    }

    /// Inserts a vote solicitation.
    pub fn insert_solicit(&mut self, solicit: Solicit) -> anyhow::Result<()> {
        if !solicit.verify_sig() && (self.tick_to_leader)(solicit.tick) == solicit.source {
            anyhow::bail!("bad signature")
        }
        if solicit.nonce != self.nonce {
            anyhow::bail!("bad nonce")
        }
        if !self.vote_solicits.contains_key(&solicit.previous)
            && !self.valid_proposals.contains_key(&solicit.previous)
        {
            anyhow::bail!("solicit not growing from anything")
        }
        if solicit.tick
            <= self
                .vote_solicits
                .get(&solicit.previous)
                .map(|s| s.tick)
                .or_else(|| self.valid_proposals.get(&solicit.previous).map(|s| s.tick))
                .unwrap()
        {
            anyhow::bail!("tick of vote solicit cannot go backwards in time lol")
        }
        if !self.tick_source.insert((solicit.tick, solicit.source)) {
            anyhow::bail!("this player already sent something for this tick")
        }
        self.vote_solicits.insert(solicit.chash(), solicit);
        Ok(())
    }

    fn lookup_len(&self, h: HashVal, memo: &mut HashMap<HashVal, u64>) -> u64 {
        if let Some(v) = memo.get(&h) {
            *v
        } else {
            let v = if self.valid_proposals.contains_key(&h) {
                0
            } else if let Some(v) = self.vote_solicits.get(&h) {
                self.lookup_len(v.previous, memo) + 1
            } else {
                0
            };
            memo.insert(h, v);
            v
        }
    }

    fn is_notarized(&self, h: HashVal) -> bool {
        self.votes
            .values()
            .filter(|v| v.voting_for == h)
            .map(|v| self.vote_map.get(&v.source).copied().unwrap_or_default())
            .sum::<u64>()
            > self.total_votes * 2 / 3
    }

    /// Produces the graphviz representation of the whole state.
    pub fn debug_graphviz(&self) -> String {
        use std::fmt::Write;
        let tips = self.get_lnc_tips();
        let mut output = String::new();
        output += "digraph G {\n";
        for (h, prop) in self.valid_proposals.iter() {
            writeln!(
                output,
                "{:?} [label={:?}, shape=diamond];",
                h.to_string(),
                String::from_utf8_lossy(&prop.body)
            )
            .unwrap();
        }
        for (h, solc) in self.vote_solicits.iter() {
            writeln!(
                output,
                "{:?} [label={:?}, shape=box, style=filled, fillcolor={}];",
                h.to_string(),
                &format!("{} [{}]", &h.to_string()[0..8], solc.tick),
                if tips.contains(h) {
                    "aliceblue"
                } else {
                    "whitesmoke"
                }
            )
            .unwrap();
            writeln!(
                output,
                "{:?} -> {:?};",
                h.to_string(),
                solc.previous.to_string()
            )
            .unwrap();
        }

        output += "}\n";
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;

    #[test]
    fn normal_case() {
        let players = (0..10).map(|_| tmelcrypt::ed25519_keygen().1).collect_vec();
        let mut core = Core::new(
            0,
            players
                .iter()
                .copied()
                .map(|p| (p.to_public(), 1))
                .collect_vec(),
            {
                let players = players.clone();
                move |i| players[(i as usize) % players.len()].to_public()
            },
        );
        for tick in 0.. {
            if tick > 100 {
                panic!("took too long to finalize");
            }
            for (pno, my_sk) in players.iter().copied().enumerate() {
                core.insert_my_prop_or_solicit(tick, my_sk, || {
                    Bytes::copy_from_slice(format!("prop-{}", pno).as_bytes())
                });
            }
            for my_sk in players.iter().copied() {
                if fastrand::f64() > 0.3 {
                    core.insert_my_votes(my_sk)
                }
            }
            if let Some(v) = core.get_finalized() {
                println!("FINALIZED!!!!");
                break;
            }
        }
        println!("{}", core.debug_graphviz());
    }
}
