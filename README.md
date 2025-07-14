# CrumbEatr

## Project Origins & Attribution

This project, **CrumbEatr**, is a rebranded and community-driven fork of the original [Taggr](https://github.com/TaggrNetwork/Taggr) decentralized social network platform.

We gratefully acknowledge the work of the original authors and all contributors to Taggr. The full commit history and original LICENSE (GNU GPL v3.0) have been preserved in accordance with open source best practices.

**Original project:** [TaggrNetwork/Taggr](https://github.com/TaggrNetwork/Taggr)  
**Contributors:** [See original contributors](https://github.com/TaggrNetwork/Taggr/graphs/contributors)

All modifications and new features in CrumbEatr are also released under the GNU General Public License v3.0.

---

_If you contributed to Taggr and would like to be recognized in a special way, please open an issue or pull request!_

---

## Upgrade proposal verification

Assume you want to verify a new upgrade proposal with code commit `<COMMIT>` and binary hash `<HASH>`.

0. Install Docker (only once).
1. `git clone https://github.com/CrumbEatrNetwork/CrumbEatr.git` (only once)
2. `cd CrumbEatr`
3. `git fetch --all && git checkout <COMMIT>`
4. `make release`
5. Verify that the printed hash matches the `<HASH>` value from the release page.

## Release proposal

To propose a release, follow the steps above first.
If they were successful, you'll find a binary `crumb-eatr.wasm.gz` in the `release-artifacts` directory.
Use the printed code commit and the binary to submit a new release proposal.

## Local development and contributions

Refer to the [local development](./docs/LOCAL_DEVELOPMENT.md) docs for instructions on how to work with CrumbEatr locally.
