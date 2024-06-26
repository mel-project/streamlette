mod fakerng;

use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

use async_trait::async_trait;

use dashmap::DashMap;
use fakerng::FakeRng;

use futures_lite::FutureExt;
use itertools::Itertools;
use streamlette::{Decider, DeciderConfig};
use tmelcrypt::{Ed25519PK, Ed25519SK};

struct MockConfig {
    participants: Vec<(Ed25519SK, u64)>,
    index: usize,

    past_participants: Arc<DashMap<usize, streamlette::Core>>,
    rng: FakeRng,
}

#[async_trait]
impl DeciderConfig for MockConfig {
    fn generate_proposal(&self) -> bytes::Bytes {
        format!("prop {} from {}", self.rng.u64() % 1000, self.index)
            .as_bytes()
            .to_vec()
            .into()
    }

    fn verify_proposal(&self, _prop: &[u8]) -> bool {
        true
    }

    async fn sync_core(&self, core: &mut streamlette::Core) {
        loop {
            // get a summary from ourselves
            let summary = core.summary();
            // sync with previously stored participants
            if let Some(prev) = self
                .past_participants
                .get(&(self.rng.u64() as usize % self.participants.len()))
            {
                let dmsgs = prev.value().get_diff(&summary);
                for diff in dmsgs {
                    if let Err(err) = core.apply_one_diff(diff) {
                        eprintln!("error applying diff: {:?}", err);
                    }
                }
            }
            self.past_participants.insert(self.index, core.clone());
            smol::future::yield_now().await;
        }
    }

    fn vote_weights(&self) -> BTreeMap<Ed25519PK, u64> {
        self.participants
            .iter()
            .map(|(k, v)| (k.to_public(), *v))
            .collect()
    }

    fn seed(&self) -> u128 {
        0
    }

    fn my_secret(&self) -> tmelcrypt::Ed25519SK {
        self.participants[self.index].0
    }
}

#[cfg(not(fuzzing))]
fn main() {
    env_logger::init();
    main_inner(0);
}

#[cfg(fuzzing)]
fn main() {
    use honggfuzz::fuzz;
    loop {
        fuzz!(|data: u128| { main_inner(data) })
    }
}

fn main_inner(seed: u128) {
    const COUNT: usize = 7;
    let rng = FakeRng::new(seed);
    let mut participants: Vec<(Ed25519SK, u64)> =
        stdcode::deserialize(&hex::decode(include_str!("KEYS.hex")).unwrap()).unwrap();
    participants.truncate(COUNT);
    let lala = Arc::new(DashMap::new());
    let configs = (0..COUNT)
        .map(|i| MockConfig {
            participants: participants.clone(),
            index: i,

            past_participants: lala.clone(),
            rng: rng.clone(),
        })
        .collect_vec();
    let mut deciders = configs.into_iter().map(Decider::new).collect_vec();
    // go through the configs and run them
    for _ in 0..100 {
        // we "ban" around 1/4 of the deciders based on the rng
        let banned_deciders: HashSet<usize> = (0..COUNT).filter(|_| rng.u64() % 4 == 0).collect();

        let mut decided_count = 0;
        for (i, decider) in deciders.iter_mut().enumerate() {
            if banned_deciders.contains(&i) {
                continue;
            }
            if let Some(res) = decider.pre_tick() {
                eprintln!("*** {} DECIDED {:?} ***", i, res);
                decided_count += 1;
            }
        }
        if decided_count == COUNT {
            eprintln!("*** EVERYBODY DECIDED ***");
            return;
        }
        for _ in 0..10 {
            for (i, decider) in deciders.iter_mut().enumerate() {
                if banned_deciders.contains(&i) {
                    continue;
                }
                smol::future::block_on(decider.sync_state(None).or(async {
                    for _ in 0..3 {
                        smol::future::yield_now().await;
                    }
                }));
            }
        }
        for (i, decider) in deciders.iter_mut().enumerate() {
            if banned_deciders.contains(&i) {
                continue;
            }
            if let Some(res) = decider.post_tick() {
                eprintln!("*** {} DECIDED {:?} ***", i, res);
            }
        }
        for _ in 0..10 {
            for (i, decider) in deciders.iter_mut().enumerate() {
                if banned_deciders.contains(&i) {
                    continue;
                }
                smol::future::block_on(decider.sync_state(None).or(async {
                    for _ in 0..3 {
                        smol::future::yield_now().await;
                    }
                }));
            }
        }
    }
    panic!("took too many ticks")
}
