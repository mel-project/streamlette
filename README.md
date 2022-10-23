# Streamlette: Streamlet, except for a single decision

We do a straightforward transformation of Streamlet into a oneshot consensus algorithm.

In Streamlet, we have a continuously growing _tree_ of blocks, where "sufficiently-buried" blocks become _finalized_.

In Streamlette, the purpose of one instance of the consensus algorithm is to eventually decide on one _conclusion_. We keep track of a tree of three different message types:

- _Proposals_ that have a "tick number". Proposals must pass a _validation function_.
- _Solicits_ that point to either the hash of a previous proposal, or the hash of a previous solicit. They also have a "tick number".
- _Votes_ that point to the hash of a solicitation or proposal.

Translating the Streamlet finalization criterion, a proposal buried by three consecutively-numbered, notarized (>2/3 voted) solicits becomes finalized. There can only be one such proposal (correctness), by a proof analogous to that of Streamlet.

## Testing, fuzzing, etc

Fuzzing a consensus implementation is really, really important. Streamlette must be generic over:

- the network backhaul
- the validation function
- the vote-power function
  and will not be tightly coupled in any way to `themelio-stf` and friends. Ideally, it should be useful as a BFT consensus for anything that needs a BFT consensus.

For fuzzing, we want to be able to deterministically reproduce runs of the consensus algorithm. This means that we must be able to externally "tick" every consensus participant rather than have it run off in the background, as well as use a deterministic RNG for, say, simulating unreliable networks. The fuzzing will check invariants like liveness and safety, and will be sanity-checked by making sure intentionally buggy logic (say, using a 50% threshold instead of 2/3 threshold) does actually lead to failures.

## Implementation architecture

- `Core`: implements the message tree. Contains methods for things like obtaining and applying diffs, as well as getting any finalized proposal. We use a diff-based, "pull" approach rather than a "push" approach to propagate messages in order to uphold the key property that _all messages sent by an honest player eventually reach all honest players_, even over an unreliable gossip network.
  - Obtain tips: get the tip hashes of the message tree
  - Obtain diff: given the "tips" of somebody else's message tree, get some subsequent messages (limited to a certain size) to grow their tree to be more like ours
  - Apply diff: inserts messages into the tree
- `Consensus`: implements the protocol, unified within a single `tick() -> Result<Option<Bytes>, Fatal>` function. `tick_to_end()` blocks and drives the `tick()` function with the usual gradually slowing clock.
  - Initial tick should be something like 1 second to ensure quick progression
  - This way, "real programs" can just `tick_to_end() -> Result<Bytes, Fatal>` while the fuzzer calls `tick()` deterministically with a "mock" configuration.
  - _Nothing_ should run off into the background. When `Consensus` drops, all resources should synchronously free.
- Everything passed around with a trait `ConsensusConfig`
  - Use trait objects and similar dynamic dispatch to avoid viral generics
  - Returns info like vote power, entropy seed, and list of public keys; a helper function produces the correct proposer for the given tickno from this info
  - Entire network abstracted into `next_diff_req(req)` and `get_diff_from_peer(req)`, both of which must return relatively quickly, or time out if that's not possible
- Only fatal errors of `Fatal` propagate to client
  - Basically, invariants not being upheld
  - Indicates an unrecoverable, >1/3 byzantine failure
  - Don't locally assert this. Not all users of Streamlette want to crash when consensus cannot be reached.
