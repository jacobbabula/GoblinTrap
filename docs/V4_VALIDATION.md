# V4 validation record

12 September 2026. 

- 54 tests passed, zero failures, errors or skips. See results/v4/tests.json
  and tests.txt. Checks cover v3 default-outcome regression, failed isolation,
  collateral cost timing, real empty feedback, recognition, adaptive/static
  avoidance, truth-label separation, constrained selection, disjoint splits,
  paired statistics, and tampered/missing trial or result rejection.
- All 912,840 trial rows replayed exactly under the saved configurations.
- Every calibration aggregate, selected setting, held-out budget aggregate and
  family aggregate was recomputed by the separate verifier implementation.
- 480 frozen selection cells, 960 held-out budget cells and 2,145 per-family
  result rows checked. Complete unique trial cells and disjoint seeds/families
  checked. Held-out violations are retained as violations, not removed.
- The full verifier ran under Python -O and uses explicit failure checks.
- Source, protocol and frozen-choice hashes matched. Hashes provide consistency,
  not independent timestamps, preregistration, authorship or authenticity.
- Paired bootstrap calculations have controlled-fixture tests for constant
  effects, shared-seed variation and incomplete/duplicate pairs. The derived
  analysis binds all CSV inputs by SHA-256. Intervals condition on fixed selected
  settings and scripts; calibration-selection and world uncertainty are omitted.
- The five-page technical brief was rendered with Poppler and every page was
  visually inspected for readable text, tables, figure labels and pagination.

The first v4 computation failed its final frozen-choice hash check because
Windows translated line endings during file writing. The protocol/choice writer
was changed to write explicit UTF-8 bytes. The design and policy selection rules
were unchanged, all tests passed, and a fresh full study was run. The incomplete
run remains at results/v4-first-run-incomplete locally and is excluded from the
distribution. The v3 package and engine remain preserved.

The shareable ZIP is verified for CRC, exact file inventory and every manifest
SHA-256. Its receipt is output/v4/package-receipt.json. Extraction and packaged
test/smoke-run checks are recorded separately in output/v4/package-smoke.json.