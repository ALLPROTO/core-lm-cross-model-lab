# Code, data, model, and evidence rights matrix

> **TERMINAL STATUS — DO NOT EXECUTE BLIND V1**
>
> Blind V1 is `CHECKPOINT_MISSED_TERMINAL_DRAFT`. It was retired without a
> scientific run and is not freezable, publishable, or executable. Every
> command and procedure in this document is preserved only as a historical,
> counterfactual specification and **MUST NOT be executed for Blind V1**. Any
> successor experiment requires a new suite ID and a fully rescheduled timeline.

| Component | Exact source identity | Declared license | Stored in Git | Required handling |
|---|---|---|:---:|---|
| Repository-authored lab code | This repository at the cited commit | MIT | Yes | Preserve the root copyright and license notice. |
| VoidToken codec source | `ALLPROTO/core-lm-benchmark@2e8d3b1591ee4a1ed822310f330317936871ff2b` | MIT | No | Verify the exact commit/tree and retain its copyright and MIT license notice. |
| UD English PUD r2.18 development corpus | [`UniversalDependencies/UD_English-PUD@e173a1be1b442faf34e7d5a502189ad5d9d1e197`](https://github.com/UniversalDependencies/UD_English-PUD/tree/e173a1be1b442faf34e7d5a502189ad5d9d1e197) | CC BY-SA 3.0 in the pinned repository metadata, README, and license text | No | Preserve attribution, identify CC BY-SA 3.0 with its URI, mark extraction/partition changes, and distribute reversible or source-derived corpus evidence under CC BY-SA 3.0 or a compatible license without added restrictions. Exact README and license bytes are archived. |
| GPT-Neo-125M model and tokenizer | [`EleutherAI/gpt-neo-125m@21def0189f5705e2521767faed922f1f15e7d7db`](https://huggingface.co/EleutherAI/gpt-neo-125m/tree/21def0189f5705e2521767faed922f1f15e7d7db) | MIT | No | Download only from the pinned revision; preserve upstream notice. |
| SmolLM2-360M model and tokenizer | [`HuggingFaceTB/SmolLM2-360M@f8027fd0eaeea54caa13c31d31b9fdc459c38b49`](https://huggingface.co/HuggingFaceTB/SmolLM2-360M/tree/f8027fd0eaeea54caa13c31d31b9fdc459c38b49) | Apache-2.0 | No | Preserve copyright, license, and NOTICE obligations where applicable. |
| Tiny StarCoder Python model and tokenizer | [`bigcode/tiny_starcoder_py@8547527bef0bc927268c1653cce6948c5c242dd1`](https://huggingface.co/bigcode/tiny_starcoder_py/tree/8547527bef0bc927268c1653cce6948c5c242dd1) | BigCode OpenRAIL-M | No | Review and comply with the complete use-based license before download or use. |
| BigCode OpenRAIL-M v1 agreement source | `bigcode/bigcode-model-license-agreement@63da045c89345c6533561b3cd933dda4a1616ea8` | Agreement text governing the Tiny StarCoder model | Yes | Preserve the exact tracked full agreement source and its hash; do not treat the model-card label alone as the complete terms. |
| Blind V1 Pythia-160M confirmatory revision | [`EleutherAI/pythia-160m@50f5173d932e8e61f858120bcb800b97af589f46`](https://huggingface.co/EleutherAI/pythia-160m/tree/50f5173d932e8e61f858120bcb800b97af589f46) | Apache-2.0 | No | Download only from the pinned revision; preserve upstream copyright and license notices. |
| Blind V1 Pythia-70M confirmatory revision | [`EleutherAI/pythia-70m@a39f36b100fe8a5377810d56c3f4789b9c53ac42`](https://huggingface.co/EleutherAI/pythia-70m/tree/a39f36b100fe8a5377810d56c3f4789b9c53ac42) | Apache-2.0 | No | Download only from the pinned revision; preserve upstream copyright and license notices. |
| Blind V1 SmolLM-135M confirmatory revision | [`HuggingFaceTB/SmolLM-135M@1d461723eec654e65efdc40cf49301c89c0c92f4`](https://huggingface.co/HuggingFaceTB/SmolLM-135M/tree/1d461723eec654e65efdc40cf49301c89c0c92f4) | Apache-2.0 | No | Download only from the pinned revision; preserve copyright, license, and NOTICE obligations where applicable. |
| Blind V1 SmolLM-360M confirmatory revision | [`HuggingFaceTB/SmolLM-360M@59f7ef243ee09a72cbc14cb054393a3e3b771d41`](https://huggingface.co/HuggingFaceTB/SmolLM-360M/tree/59f7ef243ee09a72cbc14cb054393a3e3b771d41) | Apache-2.0 | No | Download only from the pinned revision; preserve copyright, license, and NOTICE obligations where applicable. |
| Blind V1 GPT-2 124M confirmatory revision | [`openai-community/gpt2@607a30d783dfa663caf39e06633721c8d4cfcd7e`](https://huggingface.co/openai-community/gpt2/tree/607a30d783dfa663caf39e06633721c8d4cfcd7e) | MIT | No | Download only from the pinned revision; preserve the upstream MIT notice. |
| Blind V1 DistilGPT2 82M confirmatory revision | [`distilbert/distilgpt2@2290a62682d06624634c1f46a6ad5be0f47f38aa`](https://huggingface.co/distilbert/distilgpt2/tree/2290a62682d06624634c1f46a6ad5be0f47f38aa) | Apache-2.0 | No | Download only from the pinned revision; preserve upstream copyright and license notices. |
| Retired Blind V1 proposed German Wikipedia records | Exact creation revisions and raw response bytes would have appeared in the counterfactual frozen snapshot | CC BY-SA 4.0 plus Wikimedia terms | Never collected for V1 | Counterfactual V1 evidence would have preserved revision author attribution, permanent/history URL, and license link. |
| Retired Blind V1 proposed English Wikipedia records | Exact creation revisions and raw response bytes would have appeared in the counterfactual frozen snapshot | CC BY-SA 4.0 plus Wikimedia terms | Never collected for V1 | Counterfactual V1 evidence would have preserved revision author attribution, permanent/history URL, and license link. |
| Retired Blind V1 proposed French Wikipedia records | Exact creation revisions and raw response bytes would have appeared in the counterfactual frozen snapshot | CC BY-SA 4.0 plus Wikimedia terms | Never collected for V1 | Counterfactual V1 evidence would have preserved revision author attribution, permanent/history URL, and license link. |
| Runtime Python packages | Exact packages and files in the generated runtime manifest/SBOM | Per package | No | Consult the generated SBOM and each distribution's installed metadata. |
| Retired Blind V1 proposed NIST beacon exchange | The endpoint, target pulse, and HTTP exchange would have been committed by the counterfactual evidence manifest | No repository license asserted; United States government source material may include separately identified third-party content | Never collected for V1 | Counterfactual evidence would have preserved the exact endpoint, response bytes, NIST attribution, hashes, and applicable NIST website/publication notices without inferring a blanket public-domain grant. |
| NIST/DigiCert certificate chain and transport CA bytes | Exact tracked trust manifests and certificate bytes under historical protocol contours and the retired `blind_v1/trust/` draft | No repository license asserted; issuer certificate policies and terms remain applicable | Yes | Redistribute only as provenance/trust evidence, preserve issuer identity and exact hashes, and do not imply endorsement. The Blind V1 leaf was time-valid at the registered `2026-08-21T18:00:00.000Z` target, but it never became a freeze binding and must not be used to execute V1. |
| `cli/cli` v2.97.0 checksum known-answer asset | [`cli/cli@55dbb4dc6b7edb10b48e3d7fc5bccd32318d1b55`](https://github.com/cli/cli/tree/55dbb4dc6b7edb10b48e3d7fc5bccd32318d1b55), release ID `362812465` | MIT; exact upstream license and copyright notice stored beside the vector | Yes | Preserve `UPSTREAM-LICENSE`, the immutable release identity, and exact asset SHA-256. |
| GitHub-generated release-attestation known-answer record | Exact public DSSE/X.509/RFC3161 output for `cli/cli` v2.97.0 committed under historical protocol contours and `blind_v1/test-vectors/` | No repository license asserted; minimal machine-generated public cryptographic/factual record retained for reproducibility quotation | Yes | Preserve exact provenance and hashes, retain issuer identities, minimize to the verification record, and do not imply GitHub endorsement or a license grant over certificates/signatures. |
| Proposed Blind V1 GitHub API CI, tag, release, and asset responses | Exact GitHub REST response bytes would have been committed by the counterfactual canonical receipts; Blind V1 claimed no independent human review | No repository license asserted; GitHub terms remain applicable | Never collected as V1 scientific evidence | Counterfactual evidence would have preserved request URLs, server timestamps, response bytes, and hashes solely as provenance evidence, removed credentials, and never implied GitHub endorsement. |
| Proposed Blind V1 scientific measurements and manifests | Exact counterfactual evidence release | Repository policy plus source-data obligations | Never created for V1 | Counterfactual evidence would have kept provenance, hashes, attribution, and negative results intact. |

For the six Blind V1 confirmatory rows, the exact revision README bytes and
their license declarations are separately committed by
[`blind-v1-model-card-evidence.json`](blind-v1-model-card-evidence.json). The
six immutable revision trees contain no standalone `LICENSE*` or `NOTICE*`
file. Accordingly, the archive preserves the exact cards and does not claim
that a generic Apache or MIT text was an upstream file at those revisions.

The license and rights labels above reproduce pinned upstream declarations or
explicitly decline to infer a license; they are not a legal opinion or an
independent conclusion about ownership. The UD English PUD repository's
machine-readable metadata, included Google notice, and attached license are
consistent in declaring CC BY-SA 3.0. A counterfactual timely V1 freeze would
have preserved the exact declarations, attribution, and license bytes so later
upstream changes could not erase the record used at design time. V1 never
reached that freeze. These rights records remain available for offline audit
only and do not authorize a late V1 freeze, publication, or execution.
