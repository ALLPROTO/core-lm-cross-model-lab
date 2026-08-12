# Recorded RunPod adapter sweep

Status: `COMPLETE_RECORDED_EXPLORATORY_PUBLIC_REGRESSION`. All 28 registered cells completed, the Pod structural verifier accepted all retained containers, and seven representative same-Pod model replay receipts were retained.

This is an exploratory public regression, not scientific evidence or an independent replication. The producer, structural verifier, and replay verifier shared the same Pod, source, runtime, model cache, and operator-controlled attempt.

Lifecycle timestamps, cost, termination, volume deletion, and credential-cleanup fields are `OPERATOR_SELF_ATTESTED_NOT_PROVIDER_VERIFIED`. The builder validates only their schema, grammar, and internal consistency; it does not contact RunPod or claim a provider attestation.

The builder locally reconstructed every workload prompt from the exact signed-commit Git blobs and registered frames. Token IDs and available/selected token counts remain `SAME_POD_ASSERTION_NOT_LOCALLY_RETOKENIZED`, because this model-free builder does not retrieve tokenizer assets or rerun tokenization.

## Attempt audit

| Attempt | Status | Source commit | Failure code | Run-root disposition |
|---:|---|---|---|---|
| 1 | INCOMPLETE | `9fae1c0f5495cfeea3c7e4b5f93367d7d550be6c` | TRITON_NOEXEC_CACHE | REMOVED_AFTER_BOUNDED_FORENSICS |
| 2 | INCOMPLETE | `10a059d68db34f3ad9352d120171c8ca936b8fa2` | DISTILGPT2_LEGACY_CAUSAL_MASK_INCOMPATIBILITY | REMOVED_AFTER_BOUNDED_FORENSICS |
| 3 | INCOMPLETE | `bdce0b48670bfcb11caa706b99e85cff475abfa7` | OPERATOR_EXPECTED_IDENTITY_SCOPE_ERROR | NO_RUN_ROOT_CREATED_BOUNDED_FORENSICS_RETAINED |
| 4 | COMPLETE | `bdce0b48670bfcb11caa706b99e85cff475abfa7` | — | ARCHIVE_RETRIEVED_AND_VERIFIED |

The closed failure stage/code and forensic-manifest hashes are in `record.json`; free-text attempt summaries are forbidden. Incomplete attempts are preserved as negative operational history and are not counted as successful cells.

## Exact 28-cell matrix

There are no cross-cell, per-model, or global averages below. `mean KL` and `mean Δsurprisal` are protocol-defined summaries within one exact 32-token cell. The authoritative per-token arrays and token IDs are retained in `record.json`.

| # | Model | Workload | Prefill | Dense bytes | Container bytes | R | Saving | Bytes/effective token | Top-1 | Mean KL (nat) | Mean Δsurprisal (nat) | Max |Δlogit| | Free exact | Same pos. | LCP |
|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|---:|
| 1 | `qwen2.5-0.5b` | `tracked-legal-protocol-v1` | 8192 | 100663296 | 48428455 | 2.07859813 | 0.518906524 | 5911.67664 | 32/32 | 0.000868875571 | 0.00781813798 | 0.59375 | yes | 32 | 32 |
| 2 | `qwen2.5-0.5b` | `tracked-source-code-v1` | 8192 | 100663296 | 48349174 | 2.08200653 | 0.51969411 | 5901.99878 | 32/32 | 0.000557304218 | 0.00594550632 | 0.64453125 | yes | 32 | 32 |
| 3 | `qwen2.5-0.5b` | `tracked-structured-json-v1` | 8192 | 100663296 | 48170834 | 2.08971462 | 0.521465758 | 5880.22876 | 29/32 | 0.00106012878 | 0.0016291943 | 0.8125 | no | 11 | 1 |
| 4 | `qwen2.5-0.5b` | `tracked-technical-prose-v1` | 8192 | 100663296 | 48397935 | 2.07990891 | 0.519209713 | 5907.95105 | 31/32 | 0.000559823682 | -0.00702744311 | 0.5 | no | 21 | 21 |
| 5 | `smollm2-135m` | `tracked-legal-protocol-v1` | 5461 | 125821440 | 60907341 | 2.06578448 | 0.515922398 | 11153.148 | 32/32 | 0.000286829778 | -0.00277217166 | 1.46875 | yes | 32 | 32 |
| 6 | `smollm2-135m` | `tracked-source-code-v1` | 5461 | 125821440 | 60840709 | 2.06804691 | 0.516451974 | 11140.9465 | 32/32 | 0.000669182433 | -0.00442131147 | 1.09375 | yes | 32 | 32 |
| 7 | `smollm2-135m` | `tracked-structured-json-v1` | 5461 | 125821440 | 60751813 | 2.07107301 | 0.517158499 | 11124.6682 | 32/32 | 0.00146855431 | -0.00920214722 | 0.828125 | yes | 32 | 32 |
| 8 | `smollm2-135m` | `tracked-technical-prose-v1` | 5461 | 125821440 | 60933521 | 2.06489692 | 0.515714325 | 11157.942 | 31/32 | 0.00170087479 | 0.00697180671 | 0.84375 | no | 11 | 10 |
| 9 | `mistral-7b-v0.1` | `tracked-legal-protocol-v1` | 1024 | 134217728 | 65038381 | 2.06366957 | 0.5154263 | 63514.0439 | 32/32 | 0.000341869089 | -0.00169107191 | 0.1875 | yes | 32 | 32 |
| 10 | `mistral-7b-v0.1` | `tracked-source-code-v1` | 1024 | 134217728 | 64886335 | 2.0685053 | 0.516559131 | 63365.5615 | 32/32 | 0.000487736116 | 0.00158842122 | 1.2734375 | yes | 32 | 32 |
| 11 | `mistral-7b-v0.1` | `tracked-structured-json-v1` | 1024 | 134217728 | 64866092 | 2.06915083 | 0.516709954 | 63345.793 | 31/32 | 0.000147465875 | 0.00473140304 | 0.1875 | no | 31 | 0 |
| 12 | `mistral-7b-v0.1` | `tracked-technical-prose-v1` | 1024 | 134217728 | 65023130 | 2.0641536 | 0.515539929 | 63499.1504 | 31/32 | 0.0003338788 | 0.00071453637 | 0.22265625 | no | 9 | 9 |
| 13 | `pythia-14m` | `tracked-legal-protocol-v1` | 2015 | 6190080 | 2912907 | 2.1250524 | 0.529423368 | 1445.61141 | 15/32 | 0.748830411 | 0.539282287 | 13.375 | no | 1 | 0 |
| 14 | `pythia-14m` | `tracked-source-code-v1` | 2015 | 6190080 | 2869934 | 2.1568719 | 0.536365604 | 1424.28486 | 16/32 | 0.642400212 | 0.881987887 | 10.65625 | no | 0 | 0 |
| 15 | `pythia-14m` | `tracked-structured-json-v1` | 2015 | 6190080 | 2863183 | 2.16195751 | 0.53745622 | 1420.93449 | 25/32 | 0.45471157 | 0.539021929 | 13.625 | no | 0 | 0 |
| 16 | `pythia-14m` | `tracked-technical-prose-v1` | 2015 | 6190080 | 2900916 | 2.13383635 | 0.531360499 | 1439.66055 | 13/32 | 0.79191772 | 1.25721252 | 10.40625 | no | 3 | 1 |
| 17 | `distilgpt2` | `tracked-legal-protocol-v1` | 991 | 18266112 | 9168985 | 1.99216293 | 0.498033024 | 9252.2553 | 32/32 | 0.00547535518 | 0.0311701837 | 1 | yes | 32 | 32 |
| 18 | `distilgpt2` | `tracked-source-code-v1` | 991 | 18266112 | 9138781 | 1.9987471 | 0.499686578 | 9221.77699 | 32/32 | 0.000536500154 | -0.00291370262 | 1.5 | yes | 32 | 32 |
| 19 | `distilgpt2` | `tracked-structured-json-v1` | 991 | 18266112 | 9131798 | 2.00027552 | 0.500068871 | 9214.73058 | 30/32 | 0.0022743218 | 0.0115197008 | 2.25 | no | 2 | 0 |
| 20 | `distilgpt2` | `tracked-technical-prose-v1` | 991 | 18266112 | 9160421 | 1.99402538 | 0.498501871 | 9243.61352 | 32/32 | 0.00387113643 | 0.00204722777 | 4 | yes | 32 | 32 |
| 21 | `opt-125m` | `tracked-legal-protocol-v1` | 1365 | 50319360 | 24749254 | 2.03316674 | 0.508156423 | 18131.3216 | 32/32 | 0.000526860034 | -0.00268343277 | 0.25 | yes | 32 | 32 |
| 22 | `opt-125m` | `tracked-source-code-v1` | 1365 | 50319360 | 24722104 | 2.03539958 | 0.508695977 | 18111.4315 | 32/32 | 0.000133337529 | 0.00211611958 | 0.125 | yes | 32 | 32 |
| 23 | `opt-125m` | `tracked-structured-json-v1` | 1365 | 50319360 | 24714961 | 2.03598784 | 0.50883793 | 18106.1985 | 32/32 | 0.000338126163 | 0.00246703229 | 0.21875 | yes | 32 | 32 |
| 24 | `opt-125m` | `tracked-technical-prose-v1` | 1365 | 50319360 | 24740960 | 2.03384832 | 0.508321251 | 18125.2454 | 32/32 | 0.000144144842 | 0.00129862269 | 0.140625 | yes | 32 | 32 |
| 25 | `gemma-2b` | `tracked-legal-protocol-v1` | 4096 | 75497472 | 36424090 | 2.07273461 | 0.517545568 | 8892.6001 | 31/32 | 0.00123662435 | 0.00150823893 | 1.5 | no | 5 | 5 |
| 26 | `gemma-2b` | `tracked-source-code-v1` | 4096 | 75497472 | 36298489 | 2.07990674 | 0.519209213 | 8861.93579 | 31/32 | 0.00027826392 | 0.00392762461 | 16 | no | 21 | 21 |
| 27 | `gemma-2b` | `tracked-structured-json-v1` | 4096 | 75497472 | 36217494 | 2.08455814 | 0.52028203 | 8842.16162 | 24/32 | 0.000221755971 | 0.00444981344 | 4 | no | 12 | 0 |
| 28 | `gemma-2b` | `tracked-technical-prose-v1` | 4096 | 75497472 | 36428879 | 2.07246213 | 0.517482135 | 8893.76929 | 32/32 | 0.000823291631 | -0.00424371462 | 1.5 | yes | 32 | 32 |

`R = denseBF16Bytes / containerBytes`; for example, R=2 means the complete container occupies half the canonical dense BF16 bytes. It does not mean twice as many logical tokens were retained.

## What this run cannot establish

Deterministic execution controls repeatability; it is not itself a compression multiplier. This matrix uses one fixed maximum prefill per model and varies content only at that fixed length. Comparing models confounds sequence length with architecture geometry, tokenizer, cache policy, and codec configuration, so these rows cannot establish that compression grows with path length, linearly or multiplicatively.

A causal length test requires a preregistered within-model, within-workload prefill ladder while every other input remains fixed, followed by direct inspection of `R(P)` for each cell. No result here is promoted into the frozen scientific verdict.
