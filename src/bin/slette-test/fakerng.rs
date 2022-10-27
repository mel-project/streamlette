use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct FakeRng {
    rng: Arc<Mutex<fastrand::Rng>>,
    spinner: Arc<Mutex<u128>>,
}

impl FakeRng {
    /// Creates a fakerng with a pseudoseed.
    pub fn new(pseudoseed: u128) -> Self {
        Self {
            rng: Mutex::new(fastrand::Rng::with_seed(0)).into(),
            spinner: Mutex::new(pseudoseed).into(),
        }
    }

    /// Generates a u64.
    pub fn u64(&self) -> u64 {
        let modulator = {
            let mut spinner = self.spinner.lock().unwrap();
            *spinner = spinner.rotate_left(1);
            *spinner as u64
        };
        self.rng.lock().unwrap().u64(..) ^ modulator
    }
}
