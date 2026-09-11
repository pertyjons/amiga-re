//! What a datapath word actually costs, so the blit budget is a measurement
//! rather than a guess.
//!
//! The sandbox's blit budget (`maximum_sandbox_blit_words` in `amiga-operations`)
//! bounds *time*, not memory: DMA writes never enter the write log, so a long
//! blit does not grow a run's memory the way a long instruction stream does. A
//! bound on time is only defensible if somebody measured the time.
//!
//! # The worst case this reproduces
//!
//! Per datapath word the sandbox pays, at worst:
//!
//! | Cost | Worst case |
//! |---|---|
//! | `contains_word` during the preflight | 4 (one per enabled channel) |
//! | DMA accesses during execution | 4 (three reads and one write) |
//! | Region lookup per access | a **linear scan** over the mapped regions |
//! | Watchpoint matching per access | up to **64** comparisons |
//!
//! [`WorstCaseMemory`] reproduces exactly that shape — a linear region scan with
//! the target region *last*, and 64 watched ranges that are all compared and
//! none of which match, which is the most comparing per access anyone can
//! provoke. It deliberately does **not** depend on `amiga-disasm`: the blitter
//! reaches memory only through [`DmaMemory`], and keeping the benchmark on the
//! same side of that line is what lets it exist in this crate at all.
//!
//! # Running it
//!
//! ```text
//! cargo bench -p amiga-hw --bench blit_throughput
//! ```
//!
//! Release mode is the point — the constants bound what ships, and a debug
//! measurement would be an order of magnitude out. The output is the figure to
//! record beside the constants in `amiga-operations`'s `limits.rs`, along with
//! the machine it was taken on: a budget derived from a measurement nobody
//! wrote down is a guess again the first time hardware changes.
//!
//! # What it measured
//!
//! On a 13th Gen Intel Core i7-13700H, rustc 1.97.1, release profile:
//!
//! | Configuration | Per datapath word | Words per second |
//! |---|---|---|
//! | Worst case — 16 regions, 64 watchpoints | **177 ns** | 5.65 million |
//! | One region, nothing watched | **20 ns** | 51 million |
//!
//! The nine-fold spread between them is the reason the budget is set from the
//! worst case: both are legal recipes, and the bound has to hold for the
//! expensive one.
//!
//! Those figures are what chose the two constants in `limits.rs`:
//!
//! - `DEFAULT_MAXIMUM_SANDBOX_BLIT_WORDS = 2^22` — 0.74 s at the worst rate and
//!   0.08 s at the ordinary one, and about 160 full-screen five-plane clears,
//!   which is a frame's drawing with room to spare.
//! - `MAXIMUM_SANDBOX_BLIT_WORDS_CEILING = 2^25` — 5.9 s at the worst rate,
//!   which is the same order as the step ceiling's own "a couple of seconds".
//!
//! It is also what ruled out the numbers this work started with. A 2^28 ceiling
//! was described as "a few seconds"; measured, it is **47 seconds** of worst-case
//! blitting, and 2^26 is twelve. The budget went *down* from the estimate, which
//! is the outcome an unmeasured constant is least likely to reach on its own.

use std::hint::black_box;
use std::time::{Duration, Instant};

use amiga_hw::blitter::{
    BlitConditions, Blitter, Chipset, DmaMemory, DmaPolicy, OcsBlitSize, StartRequest,
};

/// Where the mapped region holding all four channels starts.
const ORIGIN: u32 = 0x0010_0000;
/// Bytes each channel walks: 64 × 1024 words.
const CHANNEL_BYTES: u32 = 64 * 1024 * 2;
/// Decoy regions ahead of the real one, so every lookup pays a full scan.
const DECOY_REGIONS: usize = 15;
/// Watched ranges compared against every access.
const WATCHPOINTS: usize = 64;
/// How long to keep blitting before reporting.
const MEASURE_FOR: Duration = Duration::from_secs(2);

/// A `DmaMemory` built to cost what the sandbox's costs, not to behave like it.
struct WorstCaseMemory {
    /// Half-open byte ranges, scanned linearly. The real one is last.
    regions: Vec<(u32, u32)>,
    words: Vec<u16>,
    /// Ranges compared against every access. None of them match, so every
    /// comparison runs — fewer would be a cheaper benchmark, not a truer one.
    watchpoints: Vec<(u32, u32)>,
    /// Accumulated so the comparisons cannot be optimised away.
    observed: u64,
}

impl WorstCaseMemory {
    /// `decoys` regions ahead of the real one and `watchpoints` ranges compared
    /// per access. The worst case is the pair the sandbox's own bounds allow;
    /// the cheap pair is what an ordinary recipe with one mapped region and
    /// nothing watched actually pays, and both are worth knowing before a
    /// default is chosen from either.
    fn new(decoys: usize, watchpoints: usize) -> Self {
        let span = CHANNEL_BYTES * 4;
        let mut regions: Vec<(u32, u32)> = (0..decoys)
            .map(|index| {
                let base = 0x0100_0000 + index as u32 * 0x2_0000;
                (base, base + 0x1_0000)
            })
            .collect();
        regions.push((ORIGIN, ORIGIN + span));
        let watchpoints = (0..watchpoints)
            .map(|index| {
                let base = 0x0200_0000 + index as u32 * 0x1000;
                (base, base + 0x100)
            })
            .collect();
        Self {
            regions,
            words: vec![0x5a5a; span as usize / 2],
            watchpoints,
            observed: 0,
        }
    }

    /// The sandbox's `Memory::locate`: a linear scan, returning an in-region
    /// offset.
    fn locate(&self, address: u32) -> Option<usize> {
        for &(start, end) in &self.regions {
            if address >= start && address + 1 < end {
                return Some(((address - start) / 2) as usize);
            }
        }
        None
    }

    /// The sandbox's `record_access`: every watched range compared, every time.
    fn record(&mut self, address: u32) {
        for &(start, end) in &self.watchpoints {
            if address >= start && address < end {
                self.observed += 1;
            }
        }
    }
}

impl DmaMemory for WorstCaseMemory {
    fn contains_word(&self, address: u32) -> bool {
        self.locate(address).is_some()
    }

    fn read_dma_word(&mut self, address: u32) -> Option<u16> {
        let index = self.locate(address)?;
        // The real region is last in the scan, so this index is inside `words`.
        let value = *self.words.get(index)?;
        self.record(address);
        Some(value)
    }

    fn write_dma_word(&mut self, address: u32, value: u16) -> Option<()> {
        let index = self.locate(address)?;
        *self.words.get_mut(index)? = value;
        self.record(address);
        Some(())
    }
}

/// Point all four channels at their own quarter of the region and arm a maximal
/// blit: `BLTSIZE` of zero is 64 words by 1024 lines, the largest OCS can do.
fn arm(blitter: &mut Blitter) -> StartRequest {
    // BLTCON0: USEA | USEB | USEC | USED, with the cookie-cut minterm so all
    // three sources genuinely reach the output.
    let _ = blitter.write_register(0x040, 0x0f00 | 0xca);
    let _ = blitter.write_register(0x042, 0x0000);
    let _ = blitter.write_register(0x044, 0xffff);
    let _ = blitter.write_register(0x046, 0xffff);
    for (index, high) in [0x050_u16, 0x04c, 0x048, 0x054].into_iter().enumerate() {
        let address = ORIGIN + index as u32 * CHANNEL_BYTES;
        let _ = blitter.write_register(high, (address >> 16) as u16);
        let _ = blitter.write_register(high + 2, address as u16);
    }
    for modulo in [0x064_u16, 0x062, 0x060, 0x066] {
        let _ = blitter.write_register(modulo, 0);
    }
    blitter
        .write_register(0x058, 0x0000)
        .start
        .expect("BLTSIZE starts a blit")
}

/// Blit for [`MEASURE_FOR`] and return the seconds one datapath word cost.
fn measure(decoys: usize, watchpoints: usize, per_blit: u64) -> f64 {
    let mut memory = WorstCaseMemory::new(decoys, watchpoints);
    let mut blitter = Blitter::new(Chipset::Ocs);
    let conditions = BlitConditions {
        dma_enabled: true,
        dma: DmaPolicy::AssumeEnabled,
        word_budget: u64::MAX,
    };

    // One blit outside the measurement, so first-touch page faults on the
    // region are not charged to the throughput.
    let start = arm(&mut blitter);
    let _ = black_box(blitter.execute(start, &mut memory, conditions));

    let mut blits = 0_u64;
    let began = Instant::now();
    while began.elapsed() < MEASURE_FOR {
        let start = arm(&mut blitter);
        let outcome = blitter.execute(start, &mut memory, conditions);
        assert_eq!(
            outcome.refused, None,
            "the benchmark blit must be performed"
        );
        black_box(&outcome);
        blits += 1;
    }
    let elapsed = began.elapsed();
    black_box(memory.observed);
    elapsed.as_secs_f64() / (blits * per_blit) as f64
}

fn main() {
    let size = OcsBlitSize::decode(0x0000);
    let per_blit = size.datapath_words();
    println!(
        "four channels enabled, {}x{} = {per_blit} datapath words per blit\n",
        size.width(),
        size.height(),
    );

    for (label, decoys, watchpoints) in [
        ("worst case", DECOY_REGIONS, WATCHPOINTS),
        ("one region, nothing watched", 0, 0),
    ] {
        let per_word = measure(decoys, watchpoints, per_blit);
        println!(
            "{label}: {} regions scanned linearly, {watchpoints} watchpoints per access",
            decoys + 1
        );
        println!(
            "  {:.1} ns per datapath word, {:.2} million words per second",
            per_word * 1e9,
            1.0 / per_word / 1e6,
        );
        for (budget, name) in [
            (4_194_304_u64, "2^22"),
            (33_554_432, "2^25"),
            (268_435_456, "2^28"),
        ] {
            println!(
                "  {name:>5} = {budget:>11} words is {:>6.2} s",
                budget as f64 * per_word
            );
        }
        println!();
    }
}
