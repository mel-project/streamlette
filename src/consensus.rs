use std::{collections::BTreeMap, time::Duration};

use arrayref::array_ref;
use async_trait::async_trait;
use bytes::Bytes;
use futures_lite::FutureExt;
use tmelcrypt::{Ed25519PK, Ed25519SK};

use crate::core::Core;

/// Encapsulates a single instance of Streamlette, that eventually comes to consensus on a single decision.
pub struct Decider {
    config: Box<dyn DeciderConfig>,
    core: Core,
    tick: u64,

    decision: Option<Bytes>,
}

impl Decider {
    /// Creates a new Decider.
    pub fn new(config: impl DeciderConfig) -> Self {
        let seed = config.seed();
        let total_votes: u64 = config.vote_weights().values().sum();
        let weights = config.vote_weights();
        let core = Core::new(config.seed(), config.vote_weights(), move |tick| {
            // we first randomly and fairly pick a number between 0 and total_votes.
            let random_point = {
                let mut state = seed.wrapping_add(tick as u128);
                let mut point = u64::MAX;
                while point >= total_votes {
                    let v = tmelcrypt::hash_single(&state.to_be_bytes());
                    state = u128::from_be_bytes(*array_ref![v, 0, 16]);
                    point = (state >> (total_votes as u128).leading_zeros()) as u64;
                }
                point
            };
            // using that random number, we then pick a player according to its weight.
            // we add the weights together until we exceed the random number; the staker we're at when that happens is the selected one
            let mut sum = 0;
            for (&pk, &weight) in weights.iter() {
                sum += weight;
                if sum > random_point {
                    return pk;
                }
            }
            unreachable!()
        });
        Self {
            config: Box::new(config),
            core,
            tick: 0,
            decision: None,
        }
    }

    /// Prints the graphivz representation of everything we have now.
    pub fn debug_graphviz(&self) -> String {
        self.core.debug_graphviz()
    }

    /// Runs the first half of the tick of the Decider. If the decision has been made, return it.
    ///
    /// Does no I/O. Either use [Decider::tick_to_end], or call the [Decider::sync_state] method periodically.
    pub fn pre_tick(&mut self) -> Option<Bytes> {
        self.core.set_max_tick(self.tick + 1);
        if let Some(v) = self.core.get_finalized() {
            self.decision = Some(v.body.clone());
        }
        if self.decision.is_some() {
            return self.decision.clone();
        }
        self.core
            .insert_my_prop_or_solicit(self.tick, self.config.my_secret(), || {
                self.config.generate_proposal()
            });
        None
    }

    /// Runs the first half of the tick of the Decider. If the decision has been made, return it.
    ///
    /// Does no I/O. Either use [Decider::tick_to_end], or call the [Decider::sync_state] method periodically.
    pub fn post_tick(&mut self) -> Option<Bytes> {
        if let Some(v) = self.core.get_finalized() {
            self.decision = Some(v.body.clone());
        }
        if self.decision.is_some() {
            return self.decision.clone();
        }
        // do our logic
        self.core.insert_my_votes(self.config.my_secret());
        self.tick += 1;
        None
    }

    /// Synchronized state, given a timeout.
    pub async fn sync_state(&mut self, timeout: Option<Duration>) {
        if let Some(timeout) = timeout {
            self.config
                .sync_core(&mut self.core)
                .or(async {
                    async_io::Timer::after(timeout).await;
                })
                .await
        } else {
            self.config.sync_core(&mut self.core).await;
        }
    }

    /// Ticks this decider until the decision has been made. We use a gradually increasing synchronization interval that starts from 1 second and increases by 10% every tick.
    pub async fn tick_to_end(mut self) -> Bytes {
        let mut interval = 1.0f64;
        loop {
            self.pre_tick();
            self.sync_state(Duration::from_secs_f64(interval / 2.0).into())
                .await;
            let result = self.post_tick();
            self.sync_state(Duration::from_secs_f64(interval / 2.0).into())
                .await;
            interval *= 1.1;
            if let Some(result) = result.as_ref() {
                return result.clone();
            }
        }
    }
}

/// Decider is a particular configuration that the consensus protocol must implement.
///
/// Using a trait instead of a struct improves ergonomics of the "callbacks", as well as "polluting" the [Decider] with a generic bound that prevents confusion between [Decider] instances deciding different sorts of facts.
#[async_trait]
pub trait DeciderConfig: Sync + Send + 'static {
    /// Generates a new proposal.
    fn generate_proposal(&self) -> Bytes;

    /// Returns whether a proposed decision is valid.
    fn verify_proposal(&self, prop: &[u8]) -> bool;

    /// Synchronizes, in a best-effort fashion, this "Core" state with other players on the network. Should *never return* and be cancel-safe; the Decider itself will timeout this as needed.
    async fn sync_core(&self, core: &mut Core);

    /// Returns a mapping of each player's public key to how many votes the player has. Must return the same value every time!
    fn vote_weights(&self) -> BTreeMap<Ed25519PK, u64>;

    /// Returns a random seed. Must return the same value every time!
    fn seed(&self) -> u128;

    /// Returns our secret key.
    fn my_secret(&self) -> Ed25519SK;
}
