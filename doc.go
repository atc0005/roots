// Copyright 2021 Google LLC
// Copyright 2025 Adam Chalkley
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package roots provides embedded:
//
//   - valid root certificates in Mozilla's Root Store
//   - valid root certificates in Mozilla's Root Store with the Email
//     (S/MIME) Trust Bit enabled
//   - valid root certificates in Mozilla's Root Store with the Websites
//     (TLS/SSL) Trust Bit enabled
//   - root certificates which have been removed from Mozilla's Root Store
//   - root certificates which are pending removal from Mozilla's Root Store
//   - certificate hashes for all sets
//
// # Recommendations
//
//   - It's recommended that only binaries, and not libraries, import this
//     package
//   - For best results this package should be kept up to date using tools
//     such as Dependabot
//
// # Use cases
//
// The provided root certificates and root certificate hashes are useful for
// diagnostic tools which evaluate certificate chains for common
// misconfiguration issues.
//
// The collections of certificate hashes are useful for identifying which of
// the provided collections an evaluated certificate belongs to.
//
// This package provides functionality intended specifically for diagnostic
// tools that perform evaluation of certificate chains and not general use
// applications/tooling. For those use cases it is recommended that you
// consider using an official platform verifier or officially maintained
// packages such as
// [golang.org/x/crypto/x509roots/fallback]
//
// While these root certificates *are* sourced directly from Mozilla, they
// lack the [additional restrictions imposed] on certain CAs or certificates
// which Mozilla applies separately via the NSS library or within Firefox and
// Thunderbird.
//
// [additional restrictions imposed]: https://wiki.mozilla.org/CA/Additional_Trust_Changes
// [golang.org/x/crypto/x509roots/fallback]: https://pkg.go.dev/golang.org/x/crypto/x509roots/fallback
package roots
