# UD English PUD development-corpus attribution

The non-scientific development control uses the exact `test` split from
**Universal Dependencies English PUD r2.18**.

- Upstream repository: <https://github.com/UniversalDependencies/UD_English-PUD>
- Release tag: `r2.18`
- Commit: `e173a1be1b442faf34e7d5a502189ad5d9d1e197`
- Git tree: `50f2ebe00ff016d2dca93f9bf6ee51c5f8493fde`
- Source file: `en_pud-ud-test.conllu`
- Source file SHA-256: `c80584f2bc2b31d5bada78a1136f9feec7ac49e5e18898db02dea434b5b8f0aa`
- License: [Creative Commons Attribution-ShareAlike 3.0 Unported](https://creativecommons.org/licenses/by-sa/3.0/)

The upstream README states that the sentences were provided by DFKI, that
Google makes the underlying text available under CC BY-SA 3.0 without
warranty, and that the syntactic/morphological annotations were added by
Google and converted or corrected by Universal Dependencies contributors.
Upstream credits include Martin Popel, Sebastian Schuster, Siva Reddy,
Christopher Manning, DFKI, Google, the professional translators, and the
original Wikipedia/news contributors. The exact upstream README and license
are preserved alongside this notice; those files are authoritative.

## Changes made by this project

The source CoNLL-U bytes are retained unchanged. For the development control,
the implementation:

1. extracts the single value following `# text = ` from each of the 1,000
   sentence blocks, without normalizing its text;
2. joins consecutive sentence values with two LF characters;
3. divides the ordered rows into 32 contiguous floor-boundary partitions;
4. serializes provenance envelopes, tokenizes the text with three pinned
   pretrained models, and produces cache containers and verification evidence.

The corpus bytes and source-reversible or source-derived development evidence
are redistributed under CC BY-SA 3.0. Repository-authored source code remains
under the root MIT license, and model assets retain their separate upstream
terms. No endorsement by the upstream authors or organizations is implied.
