//! Which leaves an audit samples, and where its randomness comes from.
//!
//! Two rules, both pure functions tested below:
//!   - **A leaf is drawn in proportion to its declared value.** Each sample is a position in [0, control total);
//!     the leaf whose range of the running sum covers it is the one disclosed. Drawing leaves by index instead would
//!     let an issuer park most of a false total in one leaf among many small genuine ones and almost never see it
//!     sampled.
//!   - **Nobody chooses the randomness alone.** The entropy mixes the operator's seed (committed before the ledger,
//!     revealed after) with the hash of a slot fixed at commit, which nobody knows when the ledger is committed. A
//!     cycle that leaves this path (the slot hash was not captured in time, or the seed was not revealed) is sampled
//!     twice as heavily.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::keccak;

use crate::constants::*;
use crate::state::AuditorEntry;
use crate::errors::TorusError;

/// Size of one SlotHashes entry: the slot (u64, little-endian) followed by its 32-byte hash.
const SLOT_HASH_ENTRY_LEN: usize = 8 + 32;
/// SlotHashes data starts with the number of entries (u64, little-endian).
const SLOT_HASH_HEADER_LEN: usize = 8;

/// What the SlotHashes sysvar says about a target slot.
#[derive(Debug, PartialEq, Eq)]
pub enum SlotPick {
    /// No block at or after the target is recorded yet.
    TooEarly,
    /// Hash of the first block at or after the target.
    Found([u8; 32]),
    /// The target has left the sysvar's window, so its hash can no longer be read.
    Lapsed,
}

/// Commitment to the operator's seed.
pub fn seed_commitment(seed: &[u8; 32]) -> [u8; 32] {
    keccak::hashv(&[&[SEED_COMMIT_TAG], seed]).0
}

/// Entropy of a cycle's sample. `secret` is the operator's revealed seed, or its commitment when nobody revealed
/// the seed in time (`tag` tells the two apart). Binding the audit's address keeps cycles independent.
pub fn mix_entropy(tag: u8, secret: &[u8; 32], slot_hash: &[u8; 32], audit: &Pubkey) -> [u8; 32] {
    keccak::hashv(&[&[tag], secret, slot_hash, audit.as_ref()]).0
}

/// Position of sample `j` in [0, total): uniform, so a leaf is drawn with probability value / total (with
/// replacement). Draws at or above the largest multiple of `total` are discarded, which removes the modulo bias.
pub fn sample_position(entropy: &[u8; 32], j: u16, total: u64) -> Result<u64> {
    require!(total > 0, TorusError::NothingToSample);
    let limit = (1u128 << 64) / total as u128 * total as u128;
    let mut draw = 0u64;
    for attempt in 0..=u8::MAX {
        let hash = keccak::hashv(&[entropy.as_ref(), &j.to_le_bytes(), &[attempt]]);
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&hash.0[..8]);
        draw = u64::from_le_bytes(bytes);
        if (draw as u128) < limit {
            break;
        }
    }
    // A draw is discarded with probability below 1/2, so all 256 being discarded does not happen in practice;
    // the last one is used rather than stalling the audit.
    Ok(draw % total)
}

/// Whether the leaf holding [lower, lower + value) of the running sum covers `position`.
pub fn covers(lower: u64, value: u64, position: u64) -> bool {
    position >= lower && position - lower < value
}

/// Doubles the sample (up to the account's capacity) and keeps the allowed defects at the same share of it.
/// Applied when a cycle leaves the prompt path, so that another draw is far less likely to pass a false ledger.
pub fn escalate(sample_size: u16, max_defects: u16) -> (u16, u16) {
    if sample_size == 0 {
        return (0, 0);
    }
    let doubled = (sample_size as usize * 2).min(MAX_SAMPLE_SIZE) as u16;
    let defects = (max_defects as u32 * doubled as u32 / sample_size as u32) as u16;
    (doubled, defects)
}

/// Reads the hash of the first block at or after `target` from the SlotHashes sysvar's data
/// (a count, then entries of slot + hash, newest first).
pub fn pick_slot_hash(data: &[u8], target: u64) -> Result<SlotPick> {
    let count = read_u64(data, 0)? as usize;
    let len = count
        .checked_mul(SLOT_HASH_ENTRY_LEN)
        .ok_or(TorusError::SlotHashesUnreadable)?;
    let entries = data
        .get(SLOT_HASH_HEADER_LEN..)
        .and_then(|rest| rest.get(..len))
        .ok_or(TorusError::SlotHashesUnreadable)?;
    if count == 0 {
        return Ok(SlotPick::TooEarly);
    }
    let slot_at = |i: usize| read_u64(entries, i * SLOT_HASH_ENTRY_LEN);
    if slot_at(0)? < target {
        return Ok(SlotPick::TooEarly);
    }
    // An entry older than the target proves every block at or after it is still listed.
    if slot_at(count - 1)? > target {
        return Ok(SlotPick::Lapsed);
    }
    let oldest_at_or_after = last_index_at_or_after(count, target, slot_at)?;
    let start = oldest_at_or_after * SLOT_HASH_ENTRY_LEN + 8;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&entries[start..start + 32]);
    Ok(SlotPick::Found(hash))
}

/// Entries are sorted newest first: the last index whose slot is at or after `target` (the first has one).
fn last_index_at_or_after(
    count: usize,
    target: u64,
    slot_at: impl Fn(usize) -> Result<u64>,
) -> Result<usize> {
    let (mut low, mut high) = (0usize, count - 1);
    while low < high {
        let mid = (low + high + 1) / 2;
        if slot_at(mid)? >= target {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    Ok(low)
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64> {
    let bytes = data
        .get(offset..offset + 8)
        .ok_or(TorusError::SlotHashesUnreadable)?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(buf))
}

/// Whether a registry entry counted when the cycle's ledger was committed: added before the commit slot and not revoked
/// before it. Changes at or after the commit slot do not count, because the cycle's randomness did not exist yet.
pub fn counted_at(entry: &AuditorEntry, committed_slot: u64) -> bool {
    entry.added_slot < committed_slot && entry.removed_slot >= committed_slot
}

/// What a draw of a cycle's auditor depends on.
#[derive(Clone, Copy)]
pub struct AuditorDraw<'a> {
    /// The cycle's entropy (mix_entropy): the operator's committed seed and a slot hash fixed at commit.
    pub entropy: &'a [u8; 32],
    /// The registry as it was at this slot (the commit slot).
    pub committed_slot: u64,
    /// The auditor being replaced, or Pubkey::default() for the first draw. Also separates the draws of one cycle.
    pub previous: Pubkey,
    /// Never drawn: the issuer and its partners (escrow and local), and for a replacement the cycle's first auditor.
    pub excluded: &'a [Pubkey],
}

/// The candidates of a draw, in registry order: the entries counted at the slot, each auditor once, minus the excluded
/// keys and the previous auditor. Entries revoked after the slot stay candidates, so a later revocation cannot change
/// how many there are (nor where the draw lands).
fn candidates(entries: &[AuditorEntry], draw: &AuditorDraw) -> Vec<AuditorEntry> {
    let mut list: Vec<AuditorEntry> = Vec::new();
    for entry in entries {
        let is_excluded = draw.excluded.contains(&entry.auditor) || entry.auditor == draw.previous;
        let is_known = list.iter().any(|candidate| candidate.auditor == entry.auditor);
        if counted_at(entry, draw.committed_slot) && !is_excluded && !is_known {
            list.push(*entry);
        }
    }
    list
}

/// Where a draw lands among `count` candidates: H(AUDITOR_DRAW_TAG || entropy || previous) mod count.
fn draw_position(draw: &AuditorDraw, count: usize) -> usize {
    let hash = keccak::hashv(&[&[AUDITOR_DRAW_TAG], draw.entropy.as_ref(), draw.previous.as_ref()]);
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&hash.0[..8]);
    // At most MAX_AUDITOR_ENTRIES candidates against 2^64 draws: the modulo bias is below 2^-57.
    (u64::from_le_bytes(bytes) % count as u64) as usize
}

/// The first draw of a cycle's auditor (designate_sample): the candidate where the draw lands. Nobody chooses it: the
/// entropy was unknown to everyone when the candidates were fixed. A candidate revoked since is drawn all the same and
/// then replaced at once (replace_auditor). None when there is no candidate.
pub fn draw_auditor(entries: &[AuditorEntry], draw: &AuditorDraw) -> Option<Pubkey> {
    let list = candidates(entries, draw);
    if list.is_empty() {
        return None;
    }
    list.get(draw_position(draw, list.len())).map(|entry| entry.auditor)
}

/// A replacement (replace_auditor): from where the draw lands, the first candidate still active, walking in registry
/// order. Revoking an auditor only skips it; it cannot move where the walk starts. None when no candidate is active.
pub fn draw_replacement(entries: &[AuditorEntry], draw: &AuditorDraw) -> Option<Pubkey> {
    let list = candidates(entries, draw);
    if list.is_empty() {
        return None;
    }
    let start = draw_position(draw, list.len());
    (0..list.len())
        .filter_map(|step| list.get((start + step) % list.len()))
        .find(|entry| entry.removed_slot == AUDITOR_NOT_REMOVED)
        .map(|entry| entry.auditor)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(byte: u8, added_slot: u64, removed_slot: u64) -> AuditorEntry {
        AuditorEntry { auditor: Pubkey::new_from_array([byte; 32]), added_slot, removed_slot }
    }

    const EXCLUDED: [Pubkey; 3] = [Pubkey::new_from_array([9; 32]), Pubkey::new_from_array([8; 32]), Pubkey::new_from_array([0; 32])];

    fn first_draw(entropy: &[u8; 32], committed_slot: u64) -> AuditorDraw<'_> {
        AuditorDraw { entropy, committed_slot, previous: Pubkey::default(), excluded: &EXCLUDED }
    }

    fn key(byte: u8) -> Option<Pubkey> {
        Some(Pubkey::new_from_array([byte; 32]))
    }

    #[test]
    fn draws_only_auditors_counted_at_the_commit() {
        let entries = [entry(1, 5, AUDITOR_NOT_REMOVED), entry(2, 20, AUDITOR_NOT_REMOVED), entry(3, 5, 8)];
        // Added after the commit (2) or revoked before it (3): only 1 is a candidate, whatever the entropy.
        for seed in 0u8..32 {
            let entropy = [seed; 32];
            assert_eq!(draw_auditor(&entries, &first_draw(&entropy, 10)), key(1));
        }
        // Added in the commit's own slot does not count; revoked at or after the commit still does.
        assert_eq!(draw_auditor(&[entry(4, 10, AUDITOR_NOT_REMOVED)], &first_draw(&[0; 32], 10)), None);
        assert_eq!(draw_auditor(&[entry(4, 5, 10)], &first_draw(&[0; 32], 10)), key(4));
    }

    #[test]
    fn never_draws_the_issuer_its_partners_or_the_previous_auditor() {
        let entries = [entry(9, 1, AUDITOR_NOT_REMOVED), entry(8, 1, AUDITOR_NOT_REMOVED), entry(1, 1, AUDITOR_NOT_REMOVED), entry(2, 1, AUDITOR_NOT_REMOVED)];
        for seed in 0u8..64 {
            let entropy = [seed; 32];
            let draw = AuditorDraw { previous: Pubkey::new_from_array([1; 32]), ..first_draw(&entropy, 10) };
            assert_eq!(draw_auditor(&entries, &draw), key(2));
        }
        assert_eq!(draw_auditor(&[entry(9, 1, AUDITOR_NOT_REMOVED)], &first_draw(&[0; 32], 10)), None);
    }

    #[test]
    fn revoking_others_does_not_move_a_replacement() {
        let all: Vec<AuditorEntry> = (1u8..=5).map(|byte| entry(byte, 1, AUDITOR_NOT_REMOVED)).collect();
        for seed in 0u8..32 {
            let entropy = [seed; 32];
            let draw = AuditorDraw { previous: Pubkey::new_from_array([7; 32]), ..first_draw(&entropy, 10) };
            let landed = draw_replacement(&all, &draw).unwrap();
            // Revoking any other candidate after the commit leaves the replacement where it was.
            for other in all.iter().filter(|candidate| candidate.auditor != landed) {
                let revoked: Vec<AuditorEntry> = all.iter().map(|e| if e.auditor == other.auditor { entry(e.auditor.to_bytes()[0], 1, 20) } else { *e }).collect();
                assert_eq!(draw_replacement(&revoked, &draw), Some(landed));
            }
            // Revoking the one it landed on only moves the walk to the next candidate in registry order.
            let position = all.iter().position(|e| e.auditor == landed).unwrap();
            let skipped: Vec<AuditorEntry> = all.iter().map(|e| if e.auditor == landed { entry(e.auditor.to_bytes()[0], 1, 20) } else { *e }).collect();
            assert_eq!(draw_replacement(&skipped, &draw), Some(all[(position + 1) % all.len()].auditor));
        }
    }

    #[test]
    fn a_replacement_needs_an_active_candidate() {
        let entries = [entry(1, 1, 15), entry(2, 1, 16)];
        assert_eq!(draw_replacement(&entries, &first_draw(&[3; 32], 10)), None);
    }

    #[test]
    fn the_draw_is_spread_evenly() {
        let entries: Vec<AuditorEntry> = (1u8..=3).map(|byte| entry(byte, 1, AUDITOR_NOT_REMOVED)).collect();
        let mut counts = [0u32; 3];
        for round in 0u32..3_000 {
            let entropy = keccak::hashv(&[&round.to_le_bytes()]).0;
            let drawn = draw_auditor(&entries, &first_draw(&entropy, 10)).unwrap();
            counts[(drawn.to_bytes()[0] - 1) as usize] += 1;
        }
        assert!(counts.iter().all(|&count| (850..=1_150).contains(&count)), "{counts:?}");
    }

    /// SlotHashes data for the given slots (newest first); each hash is its slot repeated.
    fn slot_hashes(slots: &[u64]) -> Vec<u8> {
        let mut data = (slots.len() as u64).to_le_bytes().to_vec();
        for &slot in slots {
            data.extend_from_slice(&slot.to_le_bytes());
            data.extend_from_slice(&[slot as u8; 32]);
        }
        data
    }

    fn entropy(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn positions_stay_inside_the_total() {
        for total in [1u64, 2, 7, 1_000_000, u64::MAX] {
            for j in 0..64u16 {
                assert!(sample_position(&entropy(3), j, total).unwrap() < total);
            }
        }
    }

    #[test]
    fn a_zero_total_has_nothing_to_sample() {
        assert!(sample_position(&entropy(3), 0, 0).is_err());
    }

    #[test]
    fn positions_depend_on_the_entropy_and_the_sample_number() {
        let total = 1_000_000_000u64;
        let a = sample_position(&entropy(1), 0, total).unwrap();
        assert_ne!(a, sample_position(&entropy(2), 0, total).unwrap());
        assert_ne!(a, sample_position(&entropy(1), 1, total).unwrap());
        assert_eq!(a, sample_position(&entropy(1), 0, total).unwrap());
    }

    /// The hole this module closes: one fabricated leaf holding 90% of the total among seven genuine ones. Drawn by
    /// index it escapes four samples more than half the time; drawn by value it almost never does.
    #[test]
    fn a_leaf_holding_most_of_the_total_is_almost_always_drawn() {
        let (total, fabricated_from) = (1_000_000u64, 100_000u64); // the fabricated leaf covers [100_000, 1_000_000)
        let missed = (0..=u8::MAX)
            .filter(|&n| {
                (0..4u16).all(|j| sample_position(&entropy(n), j, total).unwrap() < fabricated_from)
            })
            .count();
        // Missing it takes four draws in the genuine 10%: about 1 in 10,000.
        assert!(missed <= 1, "missed in {missed} of 256 entropies");
    }

    #[test]
    fn positions_are_spread_evenly() {
        let total = 10u64;
        let mut hits = [0u32; 10];
        for n in 0..=u8::MAX {
            for j in 0..40u16 {
                hits[sample_position(&entropy(n), j, total).unwrap() as usize] += 1;
            }
        }
        // 10,240 draws over 10 positions: 1,024 each on average.
        assert!(hits.iter().all(|&h| (850..1_200).contains(&h)), "{hits:?}");
    }

    #[test]
    fn a_leaf_covers_exactly_its_range() {
        assert!(covers(10, 5, 10));
        assert!(covers(10, 5, 14));
        assert!(!covers(10, 5, 15));
        assert!(!covers(10, 5, 9));
        assert!(!covers(10, 0, 10), "an empty leaf is never drawn");
        assert!(covers(u64::MAX - 1, 1, u64::MAX - 1), "no overflow at the top of the range");
    }

    #[test]
    fn the_seed_commitment_and_the_entropy_are_bound_to_their_inputs() {
        let audit = Pubkey::new_unique();
        assert_ne!(seed_commitment(&entropy(1)), seed_commitment(&entropy(2)));
        let base = mix_entropy(ENTROPY_SEEDED_TAG, &entropy(1), &entropy(9), &audit);
        assert_ne!(base, mix_entropy(ENTROPY_UNSEEDED_TAG, &entropy(1), &entropy(9), &audit));
        assert_ne!(base, mix_entropy(ENTROPY_SEEDED_TAG, &entropy(2), &entropy(9), &audit));
        assert_ne!(base, mix_entropy(ENTROPY_SEEDED_TAG, &entropy(1), &entropy(8), &audit));
        assert_ne!(base, mix_entropy(ENTROPY_SEEDED_TAG, &entropy(1), &entropy(9), &Pubkey::new_unique()));
    }

    #[test]
    fn escalation_doubles_the_sample_and_keeps_the_defect_share() {
        assert_eq!(escalate(29, 0), (58, 0));
        assert_eq!(escalate(21, 1), (42, 2));
        assert_eq!(escalate(200, 10), (256, 12), "capped by the account's capacity");
        assert_eq!(escalate(0, 0), (0, 0), "a zero declaration has no sample");
    }

    #[test]
    fn the_slot_hash_is_the_first_block_at_or_after_the_target() {
        let data = slot_hashes(&[20, 19, 17, 16, 12]);
        assert_eq!(pick_slot_hash(&data, 17).unwrap(), SlotPick::Found([17; 32]));
        assert_eq!(pick_slot_hash(&data, 18).unwrap(), SlotPick::Found([19; 32]), "slot 18 was skipped");
        assert_eq!(pick_slot_hash(&data, 13).unwrap(), SlotPick::Found([16; 32]));
        assert_eq!(pick_slot_hash(&data, 12).unwrap(), SlotPick::Found([12; 32]));
        assert_eq!(pick_slot_hash(&data, 20).unwrap(), SlotPick::Found([20; 32]));
    }

    #[test]
    fn a_target_not_produced_yet_is_too_early() {
        let data = slot_hashes(&[20, 19, 17]);
        assert_eq!(pick_slot_hash(&data, 21).unwrap(), SlotPick::TooEarly);
        assert_eq!(pick_slot_hash(&slot_hashes(&[]), 5).unwrap(), SlotPick::TooEarly);
    }

    #[test]
    fn a_target_older_than_the_window_has_lapsed() {
        let data = slot_hashes(&[600, 599, 100]);
        assert_eq!(pick_slot_hash(&data, 99).unwrap(), SlotPick::Lapsed);
        assert_eq!(pick_slot_hash(&data, 100).unwrap(), SlotPick::Found([100; 32]));
    }

    #[test]
    fn truncated_slot_hashes_are_rejected() {
        let mut data = slot_hashes(&[20, 19]);
        data.truncate(data.len() - 1);
        assert!(pick_slot_hash(&data, 19).is_err());
        assert!(pick_slot_hash(&[1, 2, 3], 19).is_err());
    }
}
