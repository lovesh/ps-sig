# Copilot Instructions

- Keep test-vector generation and verification strictly separate.
- Verification tests must only read committed vectors from disk and must not generate new vectors.
- Generation tests must be explicitly ignored and only run on demand.
- For Fiat-Shamir protocols, verifier-side tests must recompute challenges from public transcript data and never load challenge values from files.
- When adding new vector-backed tests, include both:
  - an ignored `generate_*` test that writes vectors
  - a non-ignored `verify_*` test that reads and verifies vectors
