// Copyright 2021 Google LLC
// Copyright 2025 Adam Chalkley
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd
//
// Code in this file inspired by or generated with the help of:
//
// - ChatGPT, OpenAI
// - Google Gemini
// - Claude (Anthropic AI assistant)

package roots

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	_ "embed"
)

//nolint:gochecknoglobals
var (

	//go:embed certificates/IncludedCACertificates.pem
	embeddedCACertsIncludedAll []byte

	//go:embed certificates/IncludedCACertificates-TrustBitWebsites.pem
	embeddedCACertsIncludedWebsites []byte

	//go:embed certificates/IncludedCACertificates-TrustBitEmail.pem
	embeddedCACertsIncludedEmail []byte

	//go:embed certificates/RemovedCACertificates.pem
	embeddedCACertsRemoved []byte

	//go:embed certificates/UpcomingRootRemovalsReport.pem
	embeddedCACertsUpcomingRemovals []byte
)

//nolint:gochecknoglobals
var (
	//go:embed hashes/IncludedCACertificateHashes.txt
	embeddedCACertsIncludedAllHashes []byte

	//go:embed hashes/IncludedCACertificateHashes-TrustBitWebsites.txt
	embeddedCACertsIncludedWebsitesHashes []byte

	//go:embed hashes/IncludedCACertificateHashes-TrustBitEmail.txt
	embeddedCACertsIncludedEmailHashes []byte

	//go:embed hashes/RemovedCACertificateHashes.txt
	embeddedCACertsRemovedHashes []byte

	//go:embed hashes/UpcomingRootRemovalsReport.txt
	embeddedCACertsUpcomingRemovalsHashes []byte
)

var (
	// ErrNoCertificatesFound indicates that no certificates were found. Since
	// certificates are embedded this is a highly unusual error condition.
	ErrNoCertificatesFound = errors.New("no certificates found")

	// ErrNoCertificateHashesFound indicates that no certificate hashes were
	// found. Since certificate hashes are embedded this is a highly unusual
	// error.
	ErrNoCertificateHashesFound = errors.New("no certificate hashes found")
)

// MustGetIncludedAllCACerts returns an embedded certificates collection
// containing a set of valid root certificates in Mozilla's Root Store.
//
// This function panics if an issue is encountered parsing the embedded
// intermediates collection; because CI validates the root certificates bundle
// generated from the upstream Mozilla report it is expected to always be in a
// valid/consistent state.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Included_Certificates
func MustGetIncludedAllCACerts() []*x509.Certificate {
	return mustParseCertificates(embeddedCACertsIncludedAll)
}

// MustGetIncludedAllCACertsHashes returns an embedded collection of
// certificate hashes for valid root certificates in Mozilla's Root Store.
//
// This function panics if an issue is encountered parsing the embedded
// intermediates collection; because CI validates the certificates bundle
// generated from the upstream Mozilla report it is expected to always be in a
// valid/consistent state.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Included_Certificates
func MustGetIncludedAllCACertsHashes() []string {
	return mustParseHashes(embeddedCACertsIncludedAllHashes)
}

// GetIncludedAllCACerts returns an embedded certificates collection
// containing a set of valid root certificates in Mozilla's Root Store.
//
// This function returns an error if an issue is encountered parsing the
// embedded certificates collection. With CI validating the certificates
// bundle generated from the upstream Mozilla report it is expected to always
// be in a valid/consistent state. Even so, this function allows the caller to
// guard against any potential issues loading certificates.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Included_Certificates
func GetIncludedAllCACerts() ([]*x509.Certificate, error) {
	return parseCertificates(embeddedCACertsIncludedAll)
}

// GetIncludedAllCACertsHashes returns an embedded collection of certificate
// hashes for valid root certificates in Mozilla's Root Store.
//
// This function returns an error if an issue is encountered parsing the
// embedded certificates collection. With CI validating the certificates
// bundle generated from the upstream Mozilla report it is expected to always
// be in a valid/consistent state. Even so, this function allows the caller to
// guard against any potential issues loading certificates.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Included_Certificates
func GetIncludedAllCACertsHashes() ([]string, error) {
	return parseHashes(embeddedCACertsIncludedAllHashes)
}

// MustGetIncludedCACertsTrustBitWebsites returns an embedded certificates
// collection containing a set of valid root certificates in Mozilla's Root
// Store with the Websites (TLS/SSL) trust bit enabled.
//
// This function panics if an issue is encountered parsing the embedded
// intermediates collection; because CI validates the root certificates bundle
// generated from the upstream Mozilla report it is expected to always be in a
// valid/consistent state.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Included_Certificates
func MustGetIncludedCACertsTrustBitWebsites() []*x509.Certificate {
	return mustParseCertificates(embeddedCACertsIncludedWebsites)
}

// MustGetIncludedCACertsTrustBitWebsitesHashes returns an embedded collection
// of certificate hashes for valid root certificates in Mozilla's Root Store
// with the Websites (TLS/SSL) trust bit enabled.
//
// This function panics if an issue is encountered parsing the embedded
// intermediates collection; because CI validates the root certificates bundle
// generated from the upstream Mozilla report it is expected to always be in a
// valid/consistent state.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Included_Certificates
func MustGetIncludedCACertsTrustBitWebsitesHashes() []string {
	return mustParseHashes(embeddedCACertsIncludedWebsitesHashes)
}

// GetIncludedCACertsTrustBitWebsites returns an embedded certificates
// collection containing a set of valid root certificates in Mozilla's Root
// Store with the Websites (TLS/SSL) trust bit enabled.
//
// This function returns an error if an issue is encountered parsing the
// embedded certificates collection. With CI validating the certificates
// bundle generated from the upstream Mozilla report it is expected to always
// be in a valid/consistent state. Even so, this function allows the caller to
// guard against any potential issues loading certificates.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Included_Certificates
func GetIncludedCACertsTrustBitWebsites() ([]*x509.Certificate, error) {
	return parseCertificates(embeddedCACertsIncludedWebsites)
}

// GetIncludedCACertsTrustBitWebsitesHashes returns an embedded collection
// of certificate hashes for valid root certificates in Mozilla's Root Store
// with the Websites (TLS/SSL) trust bit enabled.
//
// This function returns an error if an issue is encountered parsing the
// embedded certificates collection. With CI validating the certificates
// bundle generated from the upstream Mozilla report it is expected to always
// be in a valid/consistent state. Even so, this function allows the caller to
// guard against any potential issues loading certificates.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Included_Certificates
func GetIncludedCACertsTrustBitWebsitesHashes() ([]string, error) {
	return parseHashes(embeddedCACertsIncludedWebsitesHashes)
}

// MustGetIncludedCACertsTrustBitEmail returns an embedded certificates
// collection containing a set of valid root certificates in Mozilla's Root
// Store with the Email (S/MIME) trust bit enabled.
//
// This function panics if an issue is encountered parsing the embedded
// intermediates collection; because CI validates the root certificates bundle
// generated from the upstream Mozilla report it is expected to always be in a
// valid/consistent state.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Included_Certificates
func MustGetIncludedCACertsTrustBitEmail() []*x509.Certificate {
	return mustParseCertificates(embeddedCACertsIncludedEmail)
}

// MustGetIncludedCACertsTrustBitEmailHashes returns an embedded collection of
// certificate hashes for valid root certificates in Mozilla's Root Store with
// the Email (S/MIME) trust bit enabled.
//
// This function panics if an issue is encountered parsing the embedded
// intermediates collection; because CI validates the root certificates bundle
// generated from the upstream Mozilla report it is expected to always be in a
// valid/consistent state.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Included_Certificates
func MustGetIncludedCACertsTrustBitEmailHashes() []string {
	return mustParseHashes(embeddedCACertsIncludedEmailHashes)
}

// GetIncludedCACertsTrustBitEmail returns an embedded certificates
// collection containing a set of valid root certificates in Mozilla's Root
// Store with the Email (S/MIME) Trust Bit enabled.
//
// This function returns an error if an issue is encountered parsing the
// embedded certificates collection. With CI validating the certificates
// bundle generated from the upstream Mozilla report it is expected to always
// be in a valid/consistent state. Even so, this function allows the caller to
// guard against any potential issues loading certificates.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Included_Certificates
func GetIncludedCACertsTrustBitEmail() ([]*x509.Certificate, error) {
	return parseCertificates(embeddedCACertsIncludedEmail)
}

// GetIncludedCACertsTrustBitEmailHashes returns an embedded collection of
// certificate hashes for valid root certificates in Mozilla's Root Store with
// the Email (S/MIME) Trust Bit enabled.
//
// This function returns an error if an issue is encountered parsing the
// embedded certificates collection. With CI validating the certificates
// bundle generated from the upstream Mozilla report it is expected to always
// be in a valid/consistent state. Even so, this function allows the caller to
// guard against any potential issues loading certificates.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Included_Certificates
func GetIncludedCACertsTrustBitEmailHashes() ([]string, error) {
	return parseHashes(embeddedCACertsIncludedEmailHashes)
}

// MustGetRemovedCACerts returns an embedded certificates collection
// containing a set of root certificates which have been removed from
// Mozilla's Root Store.
//
// This function panics if an issue is encountered parsing the embedded
// intermediates collection; because CI validates the root certificates bundle
// generated from the upstream Mozilla report it is expected to always be in a
// valid/consistent state.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Removed_Certificates
func MustGetRemovedCACerts() []*x509.Certificate {
	return mustParseCertificates(embeddedCACertsRemoved)
}

// MustGetRemovedCACertsHashes returns an embedded collection of certificate
// hashes for root certificates which have been removed from Mozilla's Root
// Store.
//
// This function panics if an issue is encountered parsing the embedded
// intermediates collection; because CI validates the root certificates bundle
// generated from the upstream Mozilla report it is expected to always be in a
// valid/consistent state.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Removed_Certificates
func MustGetRemovedCACertsHashes() []string {
	return mustParseHashes(embeddedCACertsRemovedHashes)
}

// GetRemovedCACerts returns an embedded certificates collection containing a
// set of root certificates which have been removed from Mozilla's Root Store.
//
// This function returns an error if an issue is encountered parsing the
// embedded certificates collection. With CI validating the certificates
// bundle generated from the upstream Mozilla report it is expected to always
// be in a valid/consistent state. Even so, this function allows the caller to
// guard against any potential issues loading certificates.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Removed_Certificates
func GetRemovedCACerts() ([]*x509.Certificate, error) {
	return parseCertificates(embeddedCACertsRemoved)
}

// GetRemovedCACertsHashes returns an embedded collection of certificate
// hashes for root certificates which have been removed from Mozilla's Root
// Store.
//
// This function returns an error if an issue is encountered parsing the
// embedded certificates collection. With CI validating the certificates
// bundle generated from the upstream Mozilla report it is expected to always
// be in a valid/consistent state. Even so, this function allows the caller to
// guard against any potential issues loading certificates.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Removed_Certificates
func GetRemovedCACertsHashes() ([]string, error) {
	return parseHashes(embeddedCACertsRemovedHashes)
}

// MustGetUpcomingRemovalsCACerts returns an embedded certificates collection
// containing a set of root certificates which are pending removal from
// Mozilla's Root Store.
//
// NOTE: The returned collection may be empty if the input file is empty of
// pending removal entries (which is a normal occurrence for this report
// type).
//
// This function panics if an issue is encountered parsing the embedded
// intermediates collection; because CI validates the root certificates bundle
// generated from the upstream Mozilla report it is expected to always be in a
// valid/consistent state.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Removed_Certificates
func MustGetUpcomingRemovalsCACerts() []*x509.Certificate {
	if len(embeddedCACertsUpcomingRemovals) == 0 {
		return []*x509.Certificate{}
	}

	return mustParseCertificates(embeddedCACertsUpcomingRemovals)
}

// MustGetUpcomingRemovalsCACertsHashes returns an embedded collection of
// certificate hashes for root certificates which are pending removal from
// Mozilla's Root Store.
//
// NOTE: The returned collection may be empty if the input file is empty of
// pending removal entries (which is a normal occurrence for this report
// type).
//
// This function panics if an issue is encountered parsing the embedded
// intermediates collection; because CI validates the root certificates bundle
// generated from the upstream Mozilla report it is expected to always be in a
// valid/consistent state.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Removed_Certificates
func MustGetUpcomingRemovalsCACertsHashes() []string {
	if len(embeddedCACertsUpcomingRemovalsHashes) == 0 {
		return []string{}
	}

	return mustParseHashes(embeddedCACertsUpcomingRemovalsHashes)
}

// GetUpcomingRemovalsCACerts returns an embedded certificates collection
// containing a set of root certificates which are pending removal from
// Mozilla's Root Store.
//
// NOTE: The returned collection may be empty if the input file is empty of
// pending removal entries (which is a normal occurrence for this report
// type).
//
// This function returns an error if an issue is encountered parsing the
// embedded certificates collection. With CI validating the certificates
// bundle generated from the upstream Mozilla report it is expected to always
// be in a valid/consistent state. Even so, this function allows the caller to
// guard against any potential issues loading certificates.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Removed_Certificates
func GetUpcomingRemovalsCACerts() ([]*x509.Certificate, error) {
	if len(embeddedCACertsUpcomingRemovals) == 0 {
		return []*x509.Certificate{}, nil
	}

	return parseCertificates(embeddedCACertsUpcomingRemovals)
}

// GetUpcomingRemovalsCACertsHashes returns an embedded collection of
// certificate hashes for root certificates which are pending removal from
// Mozilla's Root Store.
//
// NOTE: The returned collection may be empty if the input file is empty of
// pending removal entries (which is a normal occurrence for this report
// type).
//
// This function returns an error if an issue is encountered parsing the
// embedded certificates collection. With CI validating the certificates
// bundle generated from the upstream Mozilla report it is expected to always
// be in a valid/consistent state. Even so, this function allows the caller to
// guard against any potential issues loading certificates.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Removed_Certificates
func GetUpcomingRemovalsCACertsHashes() ([]string, error) {
	if len(embeddedCACertsUpcomingRemovalsHashes) == 0 {
		return []string{}, nil
	}

	return parseHashes(embeddedCACertsUpcomingRemovalsHashes)
}

// parseCertificates parses PEM-encoded certificates into x509.Certificate
// values.
func parseCertificates(pemData []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate

	pemBlock := &pem.Block{}

	// Create a buffer for the PEM data.
	pemBuffer := bytes.NewBuffer(pemData)

	// Decode each PEM block
	for {
		pemBlock, pemBuffer = decodePEMBlock(pemBuffer)
		if pemBlock == nil {
			break
		}

		// Skip non-certificate blocks
		if pemBlock.Type != "CERTIFICATE" {
			continue
		}

		// Parse the certificate
		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		certificates = append(certificates, cert)
	}

	if len(certificates) == 0 {
		return nil, fmt.Errorf("PEM data invalid: %w", ErrNoCertificatesFound)
	}

	return certificates, nil
}

// mustParseCertificates parses PEM-encoded certificates into x509.Certificate
// values.
func mustParseCertificates(pemData []byte) []*x509.Certificate {
	var certificates []*x509.Certificate

	pemBlock := &pem.Block{}

	// Create a buffer for the PEM data.
	pemBuffer := bytes.NewBuffer(pemData)

	// Decode each PEM block
	for {
		pemBlock, pemBuffer = decodePEMBlock(pemBuffer)
		if pemBlock == nil {
			break
		}

		// Skip non-certificate blocks
		if pemBlock.Type != "CERTIFICATE" {
			continue
		}

		// Parse the certificate
		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			panic(fmt.Errorf("failed to parse certificate: %w", err))
		}

		certificates = append(certificates, cert)
	}

	if len(certificates) == 0 {
		panic(fmt.Errorf("PEM data invalid: %w", ErrNoCertificatesFound))
	}

	return certificates
}

func parseHashes(data []byte) ([]string, error) {
	hashes := strings.Split(string(data), "\n")

	// Remove trailing empty string, if present.
	if len(hashes) > 0 && hashes[len(hashes)-1] == "" {
		hashes = hashes[:len(hashes)-1]
	}

	if len(hashes) == 0 {
		return nil, ErrNoCertificateHashesFound
	}

	return hashes, nil
}

func mustParseHashes(data []byte) []string {
	hashes := strings.Split(string(data), "\n")

	// Remove trailing empty string, if present.
	if len(hashes) > 0 && hashes[len(hashes)-1] == "" {
		hashes = hashes[:len(hashes)-1]
	}

	if len(hashes) == 0 {
		panic(ErrNoCertificateHashesFound)
	}

	return hashes
}

// decodePEMBlock decodes a single PEM block from the buffer. A new buffer
// containing the unprocessed PEM data is returned along with the decoded PEM
// block.
func decodePEMBlock(pemBuffer *bytes.Buffer) (*pem.Block, *bytes.Buffer) {
	if pemBuffer.Len() == 0 {
		return nil, pemBuffer
	}

	block, rest := pem.Decode(pemBuffer.Bytes())
	if block == nil {
		return nil, pemBuffer
	}

	pemBuffer = bytes.NewBuffer(rest)
	return block, pemBuffer
}
