# Dominator Tree and Loop Detection

## Overview
Technical specification for **Rev-Core** systems engine.

## Specification Details
Lengauer-Tarjan algorithm for dominator tree calculation and back-edge loop detection.

## Invariants & Design Guarantees
- Zero-cost abstractions where possible.
- Safe Rust memory semantics without undefined behavior (`unsafe` strictly audited).
- Deterministic behavior under concurrent thread interleavings.
