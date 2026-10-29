# x86_64 Instruction Prefix Decoding

## Overview
Technical specification for **Rev-Core** systems engine.

## Specification Details
Decoding legacy prefixes (LOCK, REP, Segment overrides) and 64-bit REX prefixes.

## Invariants & Design Guarantees
- Zero-cost abstractions where possible.
- Safe Rust memory semantics without undefined behavior (`unsafe` strictly audited).
- Deterministic behavior under concurrent thread interleavings.
