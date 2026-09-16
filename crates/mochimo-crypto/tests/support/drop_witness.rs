//! The zeroization drop-witness, in one place because two binaries need it.
//!
//! `tests/native.rs` runs it as `secret_bytes_are_gone_after_drop`, which is
//! where the execution census demands the proof live. `tests/miri.rs` runs it
//! under the interpreter, which is the only thing that can say whether the
//! construction below is sound rather than merely appearing to work. One
//! implementation, two consumers: a second copy could drift into unsoundness
//! in the binary Miri does not execute.
//!
//! # The construction, and why it is not undefined behaviour
//!
//! `zeroization_has_no_reference_counterpart`'s own doc comment proposes
//! *"place the secret at a known address, drop it, and read that address back
//! through a raw pointer"*. An earlier session refused it as undefined
//! behaviour and was right to refuse it. **The measurement showed what actually happens,
//! and the naive version is wrong in a way neither of us predicted:**
//!
//!   * Written over a **local**, Miri did **not** report UB. It failed the
//!     assertion instead, with *32 of 32 bytes still matching the pattern* --
//!     because `drop(x)` **moves** `x` into `drop`, so the zeroing happens in
//!     the callee's frame and the address the test kept still holds the
//!     original bytes. It is a **false negative about a `Secret` that was
//!     correctly cleared**, which is worse than the UB it was refused for: it
//!     would have been read as evidence that zeroization does not work.
//!   * Written over a **`Box`**, so the allocation really is freed before the
//!     read, Miri reports exactly what it should: *"memory access failed:
//!     alloc… has been freed, so this pointer is dangling"*.
//!
//! Those two measurements together are why Miri's acceptance of the
//! construction below means something. A tool that accepted every version would
//! be telling us nothing; this one distinguishes.
//!
//! What is sound is to own the storage explicitly:
//!
//!   * `slot` is a **live local for the whole function**. `drop_in_place` ends
//!     the *object's* lifetime; it does not deallocate `slot`. Nothing here
//!     reads freed memory — the distinction the naive version misses is between
//!     an object dying and its storage dying.
//!   * `MaybeUninit<T>` never requires its contents to be a valid `T`. It is
//!     precisely the type whose job is holding storage across an object's
//!     death, which is the whole of what this observation needs.
//!   * The bytes read afterwards **are initialized**: `Zeroizing`'s `Drop`
//!     writes zeros with volatile stores, and a volatile write initializes.
//!     Reading initialized bytes as `u8` is sound.
//!   * A **fresh** pointer is derived after the drop. `as_mut_ptr()` took
//!     `&mut slot` for `drop_in_place`, which invalidates anything derived
//!     earlier; re-deriving is what keeps the second read legal.
//!
//! Miri is the arbiter of all four claims, not this comment.
//!
//! # What it cannot see, and this is larger than what it can
//!
//!   * **One allocation.** Copies the compiler made are invisible: register
//!     spills, temporaries created moving the `Secret` into the slot, and the
//!     caller's own `pattern` array, which still holds the bytes while the
//!     assertion runs.
//!   * **Nothing inside the ladder.** `expand_seed`'s output buffer and every
//!     chain intermediate are separate allocations with their own `Zeroizing`,
//!     and none of them is covered here.
//!   * It establishes that `Drop` ran and cleared **that storage**. It does not
//!     establish that no copy of the secret survives anywhere in the process,
//!     which is the property a reader is most likely to think a green means.

use core::mem::{size_of, MaybeUninit};

use mochimo_crypto::Secret;

/// What the witness observed. Returned rather than asserted so both callers
/// can report it in their own idiom.
pub struct DropObservation {
    /// Bytes compared before the drop; equal to the pattern, or the layout
    /// assumption is wrong and `pattern_seen_before_drop` is false.
    pub bytes: usize,
    pub pattern_seen_before_drop: bool,
    pub all_zero_after_drop: bool,
    /// How many bytes still match the pattern after the drop. Zero is the
    /// property; reported so a partial clear is visible as a number rather than
    /// as a bare `false`.
    pub surviving_pattern_bytes: usize,
}

/// Drop a `Secret` in storage this function owns, and read the storage back.
///
/// The pattern has **no zero bytes**, so "all zero afterwards" cannot be
/// satisfied by a byte that was already zero before the drop.
#[must_use]
pub fn observe_secret_drop<const N: usize>() -> DropObservation {
    let pattern: [u8; N] = core::array::from_fn(|i| ((i as u8) ^ 0xa7) | 1);

    // Asserted by the caller, not assumed here: if `Secret` ever stops being a
    // transparent wrapper the byte reads below are looking at the wrong thing,
    // and the caller reports that as a layout finding rather than a
    // zeroization failure.
    let layout_ok = size_of::<Secret<N>>() == N;

    let mut slot: MaybeUninit<Secret<N>> = MaybeUninit::new(Secret::new(pattern));

    // SAFETY: `slot` holds an initialized `Secret<N>`, whose sole field is a
    // `Zeroizing<[u8; N]>` wrapping `[u8; N]` -- all bytes initialized, no
    // padding. Reading those N bytes as `[u8; N]` copies initialized memory
    // out of storage this function owns and is still borrowing.
    let before: [u8; N] = unsafe { core::ptr::read(slot.as_ptr().cast::<[u8; N]>()) };

    // SAFETY: `slot` holds an initialized `Secret<N>` and has not been dropped.
    // This ends the OBJECT's lifetime; `slot`'s storage is untouched and stays
    // owned by this frame until it returns.
    unsafe { core::ptr::drop_in_place(slot.as_mut_ptr()) };

    // SAFETY: a FRESH pointer, derived after the `&mut` above rather than
    // before it. The storage is still ours, and every byte in it was written by
    // `Zeroizing`'s volatile zeroing, so all N are initialized.
    let after: [u8; N] = unsafe { core::ptr::read(slot.as_ptr().cast::<[u8; N]>()) };

    DropObservation {
        bytes: N,
        pattern_seen_before_drop: layout_ok && before == pattern,
        all_zero_after_drop: after.iter().all(|&b| b == 0),
        surviving_pattern_bytes: (0..N).filter(|&i| after[i] == pattern[i]).count(),
    }
}
