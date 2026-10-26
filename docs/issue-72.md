# Deferred EC certificates for joint Main Golden proofs

Implements [issue #72](https://github.com/0xMiden/golden-dkg/issues/72) on the
post-#71 dependency `f338f38b5c6b153fcba101ef4ca6bee81c2580e9`. The fixed native
relation in `golden-core` is unchanged. This document records engineering design
and validation; it does not grant the separate final composition/security release
approval required by `docs/issue-71.md`.

## Plan and obligations

`ec::Engine` collects public-base scalar multiplications behind opaque scalar and
point references. `point_x` materializes the native coordinate once; it cannot
remove a multiplication obligation. `assert_equal` registers both coordinates.
Consuming `finalize` enforces all registered equalities and installs a separate
windowed divisor certificate for every multiplication, even unmaterialized and
unasserted points. Dropping an unfinalized engine is a must-use diagnostic;
verifying against the complete plan rejects an omitted finalization or operation.

The dealer anchor, each receiver's DH multiplication, both message-dependent
hash-base multiplications, and each terminal pad check remain separately
certified. One canonical dealer-secret decomposition serves its anchor and all
receivers. Each receiver's DH coordinate, exact reduction and nonzero exponent
check are reused across independently sampled sharings; the hash bases and pads
remain instance-specific. Canonical reduction gadgets from #71 are retained.

The engine selects a two-, three-, or four-bit window from the complete public
scalar-use group, minimizing selector multipliers plus divisor coefficient
allocations. All operations sharing that scalar share its one-hot selectors.
Public tables are cached within finalization by full base encoding, bit count
and width. Offsets are domain-separated with framed inputs, sum to zero, and
are deterministically retried only if a public candidate is the identity.
Tables are batch-normalized outside R1CS. Scalars of at most four bits use a
direct table check; zero is excluded because these point references represent
nonidentity points. Production scalars retain the existing 257-bit canonical
representation. Singleton configurations retain #71's empty proof path.

The measured ladder baseline is preserved in signed snapshot
`c7c6795ae7b684a3f4f637546c09e3e89a171090`. It retains the original formulas and
also reuses receiver DH and reduction across sharings, as required for comparison
with the issue's projections. After measuring, the old circuits and comparison
branches were removed from the active source. The current profiler measures the
production ECIP implementation. The independent native divisor oracle remains
inside its test module.

## Certificate and scalar linkage

The recovered Secp experiment was `/private/tmp/golden-ecip-prototype` (2026-10-22).
Its shifted windows, monic divisor and three-point logarithmic-derivative
construction were reused. Its panicking Gauss-Jordan interpolation, hand-packed
table hash input and unguarded evaluations were replaced. Native witnesses now
use incremental chord products in the coordinate ring `A(x)-yB(x)`. A closing
root at the negated partial sum keeps the witness polynomial. Each chord/tangent
multiplication and checked vertical-factor division takes linear work; opposite
points and identity partial sums have explicit cases. The final sum must be
identity and the weighted degree must equal the root count before monic
normalization. This gives O(N²) field work and O(N) storage. Independent Gaussian
Hermite interpolation remains a test oracle, including repeated/opposite roots,
reordered roots and larger generated root sets. The native construction follows
the chord-product technique in Eagen,
[Zero Knowledge Proofs of Elliptic Curve Inner Products](https://eprint.iacr.org/2022/596),
Section 3.1.1. Public shifts use `H,2H,4H,...,-sum` from one framed hash per base;
independence is unnecessary for the zero-sum scalar-linkage argument.
The mathematical reference is Hall-Andersen and Aranha,
[Divisor Techniques for Elliptic Curve Protocols](https://blog.zksecurity.xyz/posts/divisor-notes/divisor-techniques.pdf),
version `681d28ac`, 2026-04-27, Lemmas 6–7 and Figure 1. The implementation uses a
short-Weierstrass model `y² = x³ + a*x + b`. A monic weighted-degree-N function
in the basis `1,x,-y,x²,-xy,...` has roots consisting of one selected public
point per window and the negated output. A line through three challenge points
checks the logarithmic-derivative identity. Every divisor evaluation and the
hidden output's line denominator has an explicit nonzero constraint; public
table denominators are checked before batch inversion.

The application requires linkage to the committed scalar, not merely knowledge
of some discrete logarithm. The engineering argument is:

1. Boolean canonical scalar bits fix exactly one selected root in each window.
2. The monic highest-weight coefficient fixes a nonzero function of exact
   weighted degree N. Its divisor coefficients and all output coordinates are
   committed before the line challenge.
3. An identity of logarithmic derivatives identifies the root multiplicities.
   Both sides have N roots and N is far below the field characteristic, so
   equality of residues lifts to equality of integer multiplicities, including
   duplicate roots and collisions with the negated output.
4. Principality forces the selected points to sum to the output. The public
   offsets sum to zero, giving exactly `[canonical scalar bits] public_base`.

The concrete randomized identity is a probabilistic test of that rational
identity. Independent engineering review checked its signs, curve equation,
monicity, reciprocal guards, selection expansion and scalar linkage. This is
not a replacement for the final security review of the concrete composition.

## Commitment and challenge schedule

Both prover and verifier build the same instance-major operation plan from
public data. Phase one allocates canonical scalar bits, native reduction
witnesses, curve coordinates, shared selectors and all divisor coefficients.
Finalization registers one randomized callback. Bulletproofs appends
`A_I1`, `A_O1` and `S1` before invoking it; only then does the engine derive the
line points from the proof transcript. Phase two allocates seven multipliers
per ECIP relation: three guarded divisor inverses, three derivative ratios and
one guarded output reciprocal. Each relation adds its own equality.

Degenerate challenge geometry and intersections with any *public* table
candidate cause at most sixteen deterministic public retries. Secret divisor
zeros or hidden output intersections return an error; they never cause
secret-dependent challenge retries. Their probability must be included in
completeness bounds. The proof family is now `/v2`, and the driver requires a
two-phase R1CS payload. Old proof and prepared-artifact families are rejected.

Capacity is counted from the complete public shape with distinct receivers,
including phase two and the half-multiplier reset. A prepared object caches one
shape's integer counts; restored artifacts fill that cache on first use.
Other shapes are checked without replacing it. The cache never stores or grows
generators, and is not serialized. Production still checks phase-one layout
parity and exact generator capacity.

## Jubjub coordinates and sampling assumptions

Jubjub's native coordinate remains Edwards `u`. The engine certifies the
birational short-Weierstrass image. For Edwards parameters `aE=-1,d`, let
`A=2(aE+d)/(aE-d)`, `B=4/(aE-d)`, and
`X=((1+v)/(1-v)+A/3)/B`, `Y=((1+v)/((1-v)u))/B`.
The native coordinate is constrained by
`u*(B*Y)=B*X-A/3` with `Y` explicitly nonzero. Nonidentity prime-order points
exclude the exceptional identity/order-two charts. The certificate forces its
output to equal a sum of subgroup table points; arbitrary torsion outputs do
not become admissible simply by satisfying the ambient curve equation.

Challenge points are sampled using each native group's hash-to-point routine,
so Jubjub challenges lie in its prime-order subgroup. The full-curve sampling
bound cannot be quoted unchanged. A conservative *engineering inference* from
Lemma 7's rational-zero bound is
`18*(d+M-1)*p/(|H|-1)^2` per unconditioned line candidate, where H is the
nonzero sampling subgroup, d=N, and M<=N after fixing selectors. Jubjub's
cofactor-eight restriction loses approximately a factor of 64 relative to
full-curve sampling. A union bound includes up to sixteen candidates and all
separately checked relations. Concrete hash-distribution and Fiat–Shamir
assumptions, adversarial grinding, exceptional events and joint extraction/
simulation remain subjects for the final composition/security review.

## Terminal batching decision

Terminal folding is **disabled**. Independently certified precursors and exact
canonical reductions determine each pad, which is a necessary starting point
for a batching argument. It does not by itself justify substituting a modular
R1CS-field sum for an integer sum modulo the inner scalar order. A production
fold would need reviewed post-commitment weights, an exact limb/carry and quotient
construction with explicit overflow bounds, and full-cost evidence against the
already small independent terminal ECIP checks. None is assumed here. No new
unchecked carry or terminal-accumulator path exists. Existing strict quotient
boundary and field-wrap-alias rejection tests remain active on both curves.

## Validation and measurements

The focused tests exercise native equality, shared-scalar/multi-base behavior,
coordinate caching, omitted finalization/operations/assertions, inconsistent
scalar witnesses, corrupt divisor coefficients, X substitutions and on-curve Y
negation. These attacks reach real proof verification without relying on the
native dealer checker. Jubjub also tests the map, negation, identity exceptions,
changed coordinate pairs and zero-denominator attacks. Full workflow tests
exercise independently sampled sharings, Random/Zero policies, constants,
restored preparation/state, singleton behavior and publicly valid tampering.

Actual measurements and reproduction commands are recorded in
[measurements/issue-72.md](measurements/issue-72.md). The issue's percentage and
capacity reductions are projections, not validation results. Terminal folding
is not included in these measurements.
