<!-- omit in toc -->
# atc0005/roots

The roots package provides embedded hashes and root certificates from the
Mozilla Root Program.

[![Latest Release](https://img.shields.io/github/release/atc0005/roots.svg?style=flat-square)](https://github.com/atc0005/roots/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/atc0005/roots.svg)](https://pkg.go.dev/github.com/atc0005/roots)
[![go.mod Go version](https://img.shields.io/github/go-mod/go-version/atc0005/roots)](https://github.com/atc0005/roots)

<!-- omit in toc -->
## Table of Contents

- [Project home](#project-home)
- [Overview](#overview)
- [Files / Assets](#files--assets)
- [Recommendations](#recommendations)
- [Requirements](#requirements)
  - [Go 1.23+](#go-123)
- [Stability](#stability)
- [Use cases](#use-cases)
- [Contributions](#contributions)
- [Origin](#origin)
- [License](#license)
  - [Code/assets](#codeassets)
  - [Mozilla root certificates](#mozilla-root-certificates)
- [References](#references)
  - [Upstream documentation](#upstream-documentation)
  - [Related projects](#related-projects)
  - [Other](#other)

## Project home

See [our GitHub repo][repo-url] for the latest code.

## Overview

This package provides functionality intended specifically for diagnostic tools
that perform evaluation of certificate chains and not general use
applications/tooling. For those use cases it is recommended that you consider
using an official platform verifier or officially maintained packages such as
[golang.org/x/crypto/x509roots/fallback](https://pkg.go.dev/golang.org/x/crypto/x509roots/fallback).

While these root certificates *are* sourced directly from Mozilla, they [lack
the additional restrictions imposed on certain CAs or
certificates](https://wiki.mozilla.org/CA/Additional_Trust_Changes) which
Mozilla applies separately via the NSS library or within Firefox and
Thunderbird.

This package provides certificates and certificate hashes for:

- valid CA (root) certificates in Mozilla's CA Certificate Program
- valid root certificates in Mozilla's Root Store with the Email (S/MIME)
  Trust Bit enabled
- valid root certificates in Mozilla's Root Store with the Websites (TLS/SSL)
  Trust Bit enabled
- removed CA (root) certificates
- upcoming CA (root) certificate removals

> [!NOTE]
>
> The audience for this functionality is primarily diagnostic tools which need
direct access to `x509.Certificate` values for certificate chain analysis
purposes and not general use applications/tooling.

See the linked documentation for more information.

## Files / Assets

> [!NOTE]
>
> While these files are provided directly as part of project releases the
> primary purpose for the `*.pem` (certificates) and `*.txt` (certificate
> hashes) files in this project is to provide embedded resources for
> diagnostic tools which might not otherwise have ready access to current
> versions of root certificates.

```console
$ tree certificates hashes mozilla_reports/
certificates
├── IncludedCACertificates-TrustBitEmail.pem
├── IncludedCACertificates-TrustBitWebsites.pem
├── IncludedCACertificates.pem
├── RemovedCACertificates.pem
└── UpcomingRootRemovalsReport.pem
hashes
├── IncludedCACertificateHashes-TrustBitEmail.txt
├── IncludedCACertificateHashes-TrustBitWebsites.txt
├── IncludedCACertificateHashes.txt
├── RemovedCACertificateHashes.txt
└── UpcomingRootRemovalsReport.txt
mozilla_reports/
├── IncludedCACertificateWithPEMReport.csv
├── RemovedCACertificateWithPEMReport.csv
└── UpcomingRootRemovalsReport.csv
```

Summary:

- CSV files are the original reports retrieved from Mozilla
  - <https://wiki.mozilla.org/CA/Included_Certificates>
  - <https://wiki.mozilla.org/CA/Removed_Certificates>
- `hashes` files are SHA-256 fingerprints of the certificates
- `certificates` files contain certificates in PEM format extracted from
  Mozilla CA reports

> [!WARNING]
>
> The `IncludedCACertificates-TrustBitEmail.*` and
> `IncludedCACertificates-TrustBitWebsites.*` files have some overlap; these
> files are intended to provide certificates which have that trust bit enabled
> but are not limited to *only* that trust bit.

## Recommendations

- It's recommended that only diagnostic tools (binaries), and not libraries,
  import this package
- For best results this package should be kept up to date using tools such as
  Dependabot

## Requirements

### Go 1.23+

If using Go 1.23 or newer your application will need to set the
`x509negativeserial` `GODEBUG` setting in your main application, your `go.mod`
file or your `go.work` file to `1`. This support is needed for parsing of some
older root certificates which have negative serial numbers.

>[!NOTE] Alternatives:
>
> - opt to not use the "removed" or "upcoming removals" CA (root) certificates
>   collections (which contain negative serial numbers)
>   - use the hashes collections instead for identifying whether an evaluated
>     root cert is in either collection
> - build with Go versions earlier than Go 1.23
>   - not recommended as earlier versions are unsupported

See also:

- <https://pkg.go.dev/crypto/x509#ParseCertificate>
- <https://golang.org/doc/godebug>
- <https://stackoverflow.com/questions/79061981>

## Stability

This package is a work-in-progress. While the intent is to (eventually)
provide stable backwards compatible changes, the current audience for this
package is the `atc0005/check-cert` project which is itself going through a
lot of changes. As a result, this package may go through further disruptive
changes to accommodate that project's needs.

It is recommended that you do not use branches directly and instead only use
release tags. Until this package's design stabilizes current branches may
provide mixed results.s

## Use cases

The provided root certificates and root certificate hashes are intended for
use by diagnostic tools when evaluating certificate chains for common
misconfiguration issues.

The collections of root certificate hashes are useful for identifying which of
the provided collections an evaluated root certificate belongs to (or which
intermediate was signed by it).

## Contributions

This project has a very narrow focus. While PRs may be accepted to resolve
typos, logic errors and enhance documentation, behavioral changes and feature
additions will likely be rejected as out of scope. If there is any doubt,
please open a new discussion and ask for feedback.

## Origin

This project is inspired by the original work of `filippo.io/intermediates`:

- <https://pkg.go.dev/filippo.io/intermediates>
- <https://github.com/FiloSottile/intermediates>

and the continued work in the fork of that project:

- <https://pkg.go.dev/github.com/atc0005/intermediates>
- <https://github.com/atc0005/intermediates>

## License

### Code/assets

See the [LICENSE](LICENSE) file for details regarding code/assets.

### Mozilla root certificates

See <https://www.ccadb.org/rootstores/usage#ccad> and/or the
`mozilla_reports/CDLA-Permissive-2.0.txt` license file for details regarding
the CA reports provided by the Mozilla project.

## References

### Upstream documentation

- <https://wiki.mozilla.org/CA>
- <https://wiki.mozilla.org/CA/Included_Certificates>
- <https://wiki.mozilla.org/CA/Removed_Certificates>

See also:

- <https://wiki.mozilla.org/CA/Intermediate_Certificates>

### Related projects

- <https://github.com/atc0005/check-cert>
- <https://github.com/atc0005/cert-payload>
- <https://github.com/atc0005/intermediates>

### Other

These resources were found while exploring existing projects as an alternative
to creating this project. While ultimately not used, these resources may be
useful to you as a source of additional information or as an alternative to
using functionality provided by this project:

- <https://github.com/breml/rootcerts>
- <https://breml.github.io/blog/2021/01/17/embed-ca-root-certificates-in-go-programs/>
- <https://github.com/golang/go/issues/43958>
- <https://github.com/golang/go/issues/57792>
- <https://pkg.go.dev/golang.org/x/crypto/x509roots/fallback>

<!-- Footnotes here  -->

[repo-url]: <https://github.com/atc0005/roots>  "This project's GitHub repo"
