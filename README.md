# Benefaction

> For who among you, wanting to build a tower, would not first sit down and determine the costs that are required, to see if he has the means to complete it? Otherwise, after he will have laid the foundation and not been able to finish it, everyone who sees it may begin to mock him, saying: ‘This man began to build what he was not able to finish.’

We began Sigil and are proud of the work we have performed to finish it. We would love to continue working on it. Benefaction is a solution.

## Building Contracts

The contents of [`contracts`](./contracts/) are a standard `forge` project. We have helper goals in the [Makefile](./Makefile) for building and deploying. To build the contracts, simply `make build`. To test, simply `make test`. Refer to specific deployment scripts for more information; configuration is performed directly in the file.

# Security

If you discover any bug; flaw; issue; dæmonic incursion; or other malicious, negligent, or incompetent action that impacts the security of any of these projects please responsibly disclose them to us; instructions are available [here](./SECURITY.md).

# License

The [license](./LICENSE) for all of our original work is `LicenseRef-VPL WITH AGPL-3.0-only`. This includes every asset in this repository: code, documentation, images, branding, and more. You are licensed to use all of it so long as you maintain _maximum possible virality_ and our copyleft licenses.

Permissive open source licenses are tools for the corporate subversion of libre software; visible source licenses are an even more malignant scourge. All original works in this project are to be licensed under the most aggressive, virulently-contagious copyleft terms possible. To that end everything is licensed under the [Viral Public License](./licenses/LicenseRef-VPL) coupled with the [GNU Affero General Public License v3.0](./licenses/AGPL-3.0-only) for use in the event that some unaligned party attempts to weasel their way out of copyleft protections. In short: if you use or modify anything in this project for any reason, your project must be licensed under these same terms.

For art assets specifically, in case you want to further split hairs or attempt to weasel out of this virality, we explicitly license those under the viral and copyleft [Free Art License 1.3](./licenses/FreeArtLicense-1.3).

# Original Licenses

We stand on the shoulders of giants. This repository contains a fork of upstream the upstream [Uniswap Continuous Clearing Auction](https://github.com/Uniswap/continuous-clearing-auction) which we modify and run for Sigil's own needs. This original project is licensed under the [`MIT`](./original_licenses/MIT) license, the original text of which has been maintained in the [`original_licenses/`](./original_licenses/) directory. The commit hash of initial divergence is `968e4251bfb0595155a11b94ffd0c8e05adc2701`; our license only applies to any of our own code or modifications that have not been upstreamed and absolutely does not apply to any original code or future upstream code we may choose to merge.
