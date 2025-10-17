// Copyright 2021 Google LLC
// Copyright 2025 Adam Chalkley
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

//go:build generate
// +build generate

// Tool used to generate root certificate hashes and certificates in the
// Mozilla Root Program.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/csv"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"
)

//go:generate go run generate.go

var (
	// ErrMissingEntries indicates that expected input entries were not found.
	ErrMissingEntries = errors.New("missing expected entries")
)

// The Mozilla CA Certificate Program's list of included root certificates is
// stored in a file called certdata.txt in the Mozilla source code management
// system.
//
// The following URLs are for reports that are generated once per day from the
// certdata.txt file.
//
// See these URLs for further information:
//
// https://wiki.mozilla.org/CA/Included_Certificates
// https://wiki.mozilla.org/CA/Removed_Certificates
const (
	// urlIncludedCACertificatesReport is the URL to a report of all included
	// CA root certificates (CSV with PEM of raw certificate data).
	urlIncludedCACertificatesReport = "https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportPEMCSV"

	// urlRootInclusionsInProgressReport is the URL to a report of all CA root
	// certificates in the process of being added to the Mozilla Root store.
	//
	// NOTE: This report doesn't (as of 2025-03-26) offer PEM files for
	// ingest.
	//
	// urlRootInclusionsInProgressReport = "https://ccadb.my.salesforce-sites.com/mozilla/UpcomingRootInclusionsReportCSVFormat"

	// urlRemovedCACertificatesReport is the URL to a report of the removed CA
	// certificates (CSV with PEM of raw certificate data).
	urlRemovedCACertificatesReport = "https://ccadb.my.salesforce-sites.com/mozilla/RemovedCACertificateReportPEMCSV"

	// urlUpcomingCACertificateRemovalsReport is the URL to a report of the
	// upcoming CA certificate removals (CSV with PEM of raw certificate
	// data). It is not uncommon for this report to only contain the header
	// row.
	urlUpcomingCACertificateRemovalsReport = "https://ccadb.my.salesforce-sites.com/mozilla/UpcomingRootRemovalsReportPEMCSV"
)

// Output files for the original reports.
const (
	csvOutputCACertsIncluded         = "IncludedCACertificateWithPEMReport.csv"
	csvOutputCACertsRemoved          = "RemovedCACertificateWithPEMReport.csv"
	csvOutputCACertsUpcomingRemovals = "UpcomingRootRemovalsReport.csv"
)

// Output files for the generated root bundles.
const (
	pemOutputCACertsIncludedAll      = "IncludedCACertificates.pem"
	pemOutputCACertsIncludedWebsites = "IncludedCACertificates-TrustBitWebsites.pem"
	pemOutputCACertsIncludedEmail    = "IncludedCACertificates-TrustBitEmail.pem"
	pemOutputCACertsRemoved          = "RemovedCACertificates.pem"
	pemOutputCACertsUpcomingRemovals = "UpcomingRootRemovalsReport.pem"
)

// Output files for the root hashes.
const (
	hashesOutputCACertsIncludedAll      = "IncludedCACertificateHashes.txt"
	hashesOutputCACertsIncludedWebsites = "IncludedCACertificateHashes-TrustBitWebsites.txt"
	hashesOutputCACertsIncludedEmail    = "IncludedCACertificateHashes-TrustBitEmail.txt"
	hashesOutputCACertsRemoved          = "RemovedCACertificateHashes.txt"
	hashesOutputCACertsUpcomingRemovals = "UpcomingRootRemovalsReport.txt"
)

const counterOutputFile = "count.go"

// Known keywords in Mozilla reports used to indicate which Trust Bit is set
// for a CA certificate.
const (
	trustBitsKeywordWebsites = "Websites"
	trustBitsKeywordEmail    = "Email"
)

// Example pattern observed in the csvOutputCACertsIncluded file: "2024.11.30"
const distrustForDateLayout = "2006.01.02"

type columnHeaderAssertion struct {
	InputFile      string
	ExpectedHeader string
	ActualHeader   string
	ColumnNum      int
}

type rootCertEntry struct {
	Owner                     string
	IssuerOrg                 string
	Subject                   string
	TrustBitTLS               bool
	TrustBitEmail             bool
	DistrustForTLSAfterDate   time.Time
	DistrustForSMIMEAfterDate time.Time
	PEM                       string
	Hash                      [sha256.Size]byte
}

type inputCSVColumns struct {
	Subject                             int
	SubjectHeaderName                   string
	Owner                               int
	OwnerHeaderName                     string
	IssuerOrg                           int
	IssuerOrgHeaderName                 string
	Hash                                int
	HashHeaderName                      string
	PEM                                 int
	PEMHeaderName                       string
	Comments                            int
	CommentsHeaderName                  string
	TrustBits                           int
	TrustBitsHeaderName                 string
	DistrustForTLSAfterDate             int
	DistrustForSMIMEAfterDate           int
	DistrustForTLSAfterDateHeaderName   string
	DistrustForSMIMEAfterDateHeaderName string
}

// TODO: Create a "bucket" to hold args needed for generate functions instead
// of relying on global constants directly.
//
// type generateArgs struct {
// 	InputFile string
//
// }

type processingOptions struct {
	TrustBitFilterKeyword string
	IgnoreDecodeErrors    bool
	IgnoreParseErrors     bool
	IgnoreEmptyEntries    bool
}

type writtenCounterLog struct {
	CACertsIncludedAll            int
	CACertsIncludedWebsites       int
	CACertsIncludedEmail          int
	CACertsIncludedHashesAll      int
	CACertsIncludedHashesWebsites int
	CACertsIncludedHashesEmail    int
	CACertsRemoved                int
	CACertsRemovedHashes          int
	CACertsUpcomingRemovals       int
	CACertsUpcomingRemovalsHashes int
}

func main() {
	// Emulate returning exit code from main function by "queuing up" a
	// default exit code that matches expectations, but allow explicitly
	// setting the exit code in such a way that is compatible with using
	// deferred function calls throughout the application.
	var appExitCode int
	defer func(code *int) {
		var exitCode int
		if code != nil {
			exitCode = *code
		}
		os.Exit(exitCode)
	}(&appExitCode)

	log.Print("Downloading CSV reports")

	if err := downloadCSVFile(urlIncludedCACertificatesReport, csvOutputCACertsIncluded); err != nil {
		log.Printf("Failed to download CSV file %s: %v", csvOutputCACertsIncluded, err)

		appExitCode = 1
		return
	}

	if err := downloadCSVFile(urlRemovedCACertificatesReport, csvOutputCACertsRemoved); err != nil {
		log.Printf("Failed to download CSV file %s: %v", csvOutputCACertsRemoved, err)

		appExitCode = 1
		return
	}

	if err := downloadCSVFile(urlUpcomingCACertificateRemovalsReport, csvOutputCACertsUpcomingRemovals); err != nil {
		log.Printf("Failed to download CSV file %s: %v", csvOutputCACertsUpcomingRemovals, err)

		appExitCode = 1
		return
	}

	var outputLog writtenCounterLog

	if err := generateAllRootsFiles(&outputLog); err != nil {
		log.Print(err)

		appExitCode = 1
		return
	}

	if err := generateRemovedRootsFiles(&outputLog); err != nil {
		log.Print(err)

		appExitCode = 1
		return
	}

	if err := generateUpcomingRootRemovalsFiles(&outputLog); err != nil {
		log.Print(err)

		appExitCode = 1
		return
	}

	log.Printf("Generating expected counts record file %q for next CI tests validation", counterOutputFile)

	if err := writeCounterLog(counterOutputFile, outputLog); err != nil {
		log.Printf(
			"Failed to generate output counter file %s: %v",
			counterOutputFile,
			err,
		)

		appExitCode = 1
		return
	}

	log.Printf("Wrote %d roots to %q", outputLog.CACertsIncludedAll, pemOutputCACertsIncludedAll)
	log.Printf("Wrote %d hashes to %q", outputLog.CACertsIncludedHashesAll, hashesOutputCACertsIncludedAll)

	log.Printf("Wrote %d roots to %q", outputLog.CACertsIncludedWebsites, pemOutputCACertsIncludedWebsites)
	log.Printf("Wrote %d hashes to %q", outputLog.CACertsIncludedHashesWebsites, hashesOutputCACertsIncludedWebsites)

	log.Printf("Wrote %d roots to %q", outputLog.CACertsIncludedEmail, pemOutputCACertsIncludedEmail)
	log.Printf("Wrote %d hashes to %q", outputLog.CACertsIncludedHashesEmail, hashesOutputCACertsIncludedEmail)

	log.Printf("Wrote %d roots to %q", outputLog.CACertsRemoved, pemOutputCACertsRemoved)
	log.Printf("Wrote %d hashes to %q", outputLog.CACertsRemovedHashes, hashesOutputCACertsRemoved)

	log.Printf("Wrote %d roots to %q", outputLog.CACertsUpcomingRemovals, pemOutputCACertsUpcomingRemovals)
	log.Printf("Wrote %d hashes to %q", outputLog.CACertsUpcomingRemovalsHashes, hashesOutputCACertsUpcomingRemovals)
}

func downloadCSVFile(url string, outputFilename string) error {
	c := &http.Client{Timeout: 1 * time.Minute}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Print(err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(
			"GET got %d: %v", resp.StatusCode, resp.Status,
		)
	}

	csvFile, err := os.Create(filepath.Clean(outputFilename))
	if err != nil {
		return err
	}
	defer func() {
		if err := csvFile.Close(); err != nil {
			// Ignore "file already closed" errors from our explicit file
			// close attempt at end of this function.
			if !errors.Is(err, os.ErrClosed) {
				log.Printf(
					"error occurred closing file %q: %v",
					outputFilename,
					err,
				)
			}
		}
	}()

	_, err = io.Copy(csvFile, resp.Body)
	if err != nil {
		return err
	}

	return csvFile.Close()
}

// generateRootCertEntries receives an input CSV file and generates a
// collection of rootCertEntry values using the given inputCSVColumns value to
// locate required input columns.
//
// NOTE: The inputCSVColumn value expects zero-based numbers, so to specify
// column 5 you would provide the number 4.
// func generateRootCertEntries(inputCSVFile string, outputPEMFile string, csvColumns inputCSVColumns, options parsingOptions) (int, []rootCertEntry, error) {
func generateRootCertEntries(inputCSVFile string, csvColumns inputCSVColumns, options processingOptions) ([]rootCertEntry, error) {
	var roots []rootCertEntry
	seen := make(map[[sha256.Size]byte]bool)

	csvFile, err := os.Open(filepath.Clean(inputCSVFile))
	if err != nil {
		return nil, err
	}

	r := csv.NewReader(csvFile)
	header, err := r.Read()
	if err != nil {
		return nil, err
	}

	assertions := []columnHeaderAssertion{
		{
			InputFile:      inputCSVFile,
			ExpectedHeader: csvColumns.PEMHeaderName,
			ActualHeader:   header[csvColumns.PEM],
			ColumnNum:      csvColumns.PEM,
		},
		{
			InputFile:      inputCSVFile,
			ExpectedHeader: csvColumns.CommentsHeaderName,
			ActualHeader:   header[csvColumns.Comments],
			ColumnNum:      csvColumns.Comments,
		},
		{
			InputFile:      inputCSVFile,
			ExpectedHeader: csvColumns.TrustBitsHeaderName,
			ActualHeader:   header[csvColumns.TrustBits],
			ColumnNum:      csvColumns.TrustBits,
		},
	}

	if err := assertExpectedHeaderValues(assertions); err != nil {
		return nil, err
	}

	var lineCounter int
	var skipErrCounter int
	for {
		lineCounter++

		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		// Trim any single quotes surrounding PEM data (as observed in the
		// revoked certs input file).
		record[csvColumns.PEM] = strings.Trim(record[csvColumns.PEM], "'")

		b, _ := pem.Decode([]byte(record[csvColumns.PEM]))
		if b == nil {
			// FIXME: Temporary workaround for:
			//
			// PEM too large to save directly in CCADB.\nPEM is here: https://crt.sh/?d=91478107
			//
			// We could hotfix this by retrieving the cert and inserting it into
			// this position of the collection.
			if strings.Contains(record[csvColumns.Comments], "too large") {
				log.Printf("Skipping entry %d for %q due to 'too large' comment in report", lineCounter, record[csvColumns.Subject])
				skipErrCounter++
				continue
			}

			if options.IgnoreDecodeErrors {
				log.Printf("Decode error for entry %d for %q; ignoring this error type as requested", lineCounter, record[csvColumns.Subject])
				skipErrCounter++
				continue
			}

			return nil, fmt.Errorf("record %d is not valid PEM: %#v", lineCounter, record)
		}

		if _, err := x509.ParseCertificate(b.Bytes); err != nil {
			if strings.Contains(err.Error(), "x509: invalid key usage") {
				if strings.Contains(record[csvColumns.Comments], "malformed") {
					log.Printf("Skipping entry %d for %s due to 'malformed' comment in report", lineCounter, record[csvColumns.Subject])
					skipErrCounter++
					continue
				}
			}

			// if strings.Contains(err.Error(), "failed to parse dnsName constraint") {
			// 	log.Printf("Parsing error occurred for entry %d: %v", lineCounter, err)
			// 	log.Printf("Skipping record %d due to presumed formatting issue with cert", lineCounter)
			// 	skipErrCounter++
			// 	continue
			// }

			if options.IgnoreParseErrors {
				log.Printf("Parse error for entry %d for %q; ignoring this error type as requested", lineCounter, record[csvColumns.Subject])
				skipErrCounter++
				continue
			}

			log.Printf("%#v", record)

			return nil, fmt.Errorf(
				"invalid certificate for entry %d for %s: %w",
				lineCounter,
				record[csvColumns.Subject],
				err,
			)
		}
		hash := sha256.Sum256(b.Bytes)
		if seen[hash] {
			log.Printf("Duplicate record: %v", record[csvColumns.Subject])
			continue
		}
		seen[hash] = true

		distrustTLSAfterDate, err := getDistrustAfterDate(
			csvColumns.DistrustForTLSAfterDateHeaderName,
			record[csvColumns.DistrustForTLSAfterDate],
			distrustForDateLayout,
		)

		if err != nil {
			return nil, fmt.Errorf(
				"invalid entry %d for %s; invalid TLS distrust date for non-empty field value %q: %w",
				lineCounter,
				record[csvColumns.Subject],
				record[csvColumns.DistrustForTLSAfterDate],
				err,
			)
		}

		distrustSMIMEAfterDate, err := getDistrustAfterDate(
			csvColumns.DistrustForSMIMEAfterDateHeaderName,
			record[csvColumns.DistrustForSMIMEAfterDate],
			distrustForDateLayout,
		)

		if err != nil {
			return nil, fmt.Errorf(
				"invalid entry %d for %s; invalid TLS distrust date for non-empty field value %q: %w",
				lineCounter,
				record[csvColumns.Subject],
				record[csvColumns.DistrustForSMIMEAfterDate],
				err,
			)
		}

		roots = append(roots, rootCertEntry{
			Owner:                     record[csvColumns.Owner],
			IssuerOrg:                 record[csvColumns.IssuerOrg],
			Subject:                   record[csvColumns.Subject],
			TrustBitTLS:               strings.Contains(record[csvColumns.TrustBits], trustBitsKeywordWebsites),
			TrustBitEmail:             strings.Contains(record[csvColumns.TrustBits], trustBitsKeywordEmail),
			DistrustForTLSAfterDate:   distrustTLSAfterDate,
			DistrustForSMIMEAfterDate: distrustSMIMEAfterDate,
			PEM:                       record[csvColumns.PEM],
			Hash:                      hash,
		})
	}

	if lineCounter == 0 && !options.IgnoreEmptyEntries {
		return nil, fmt.Errorf(
			"failed to parse input file %s: %w",
			inputCSVFile,
			ErrMissingEntries,
		)
	}

	sort.Slice(roots, func(i, j int) bool {
		if roots[i].Owner != roots[j].Owner {
			return roots[i].Owner < roots[j].Owner
		}
		if roots[i].Subject != roots[j].Subject {
			return roots[i].Subject < roots[j].Subject
		}
		return bytes.Compare(roots[i].Hash[:], roots[j].Hash[:]) < 0
	})

	if skipErrCounter != 0 {
		log.Printf("NOTE: Ignored %d parse/decode errors for input file %q", skipErrCounter, inputCSVFile)
	}

	return roots, nil
}

// generatePEMFile receives an input CSV file and generates an output PEM file
// using the given inputCSVColumns value to locate required input
// columns.
//
// NOTE: The inputCSVColumn value expects zero-based numbers, so to specify
// column 5 you would provide the number 4.
func generatePEMFile(entries []rootCertEntry, outputPEMFile string, csvColumns inputCSVColumns, options processingOptions) (int, error) {
	if len(entries) == 0 && !options.IgnoreEmptyEntries {
		return 0, fmt.Errorf(
			"failed to generate output file %s: %w",
			outputPEMFile,
			ErrMissingEntries,
		)
	}

	fh, err := os.Create(filepath.Clean(outputPEMFile))
	if err != nil {
		return 0, err
	}

	defer func() {
		if err := fh.Close(); err != nil {
			// Ignore "file already closed" errors from our explicit file
			// close attempt at end of this function.
			if !errors.Is(err, os.ErrClosed) {
				log.Printf(
					"error occurred closing file %q: %v",
					outputPEMFile,
					err,
				)
			}
		}
	}()

	for _, cert := range entries {
		trustBits := make([]string, 0, 2)

		if cert.TrustBitEmail {
			trustBits = append(trustBits, trustBitsKeywordEmail)
		}
		if cert.TrustBitTLS {
			trustBits = append(trustBits, trustBitsKeywordWebsites)
		}

		_, err := io.WriteString(fh, "# Owner: "+cert.Owner+"\n")
		if err != nil {
			return 0, err
		}

		_, err = io.WriteString(fh, "# IssuerOrg: "+cert.IssuerOrg+"\n")
		if err != nil {
			return 0, err
		}

		_, err = io.WriteString(fh, "# Subject: "+cert.Subject+"\n")
		if err != nil {
			return 0, err
		}

		// FIXME: Adding this mostly for verification/troubleshooting purposes
		// during initial development phase.
		if len(trustBits) > 0 {
			_, err = io.WriteString(fh, fmt.Sprintf("# Trust Bits: %v\n", trustBits))
			if err != nil {
				return 0, err
			}
		}

		// FIXME: Adding this mostly for verification/troubleshooting purposes
		// during initial development phase.
		if !cert.DistrustForTLSAfterDate.IsZero() {
			_, err = io.WriteString(fh, fmt.Sprintf(
				"# Distrust for TLS After Date: %s\n",
				cert.DistrustForTLSAfterDate.Format(distrustForDateLayout),
			))
			if err != nil {
				return 0, err
			}
		}

		// FIXME: Adding this mostly for verification/troubleshooting purposes
		// during initial development phase.
		if !cert.DistrustForSMIMEAfterDate.IsZero() {
			_, err = io.WriteString(fh, fmt.Sprintf(
				"# Distrust for S/MIME After Date: %s\n",
				cert.DistrustForSMIMEAfterDate.Format(distrustForDateLayout),
			))
			if err != nil {
				return 0, err
			}
		}

		_, err = io.WriteString(fh, cert.PEM)
		if err != nil {
			return 0, err
		}

		_, err = io.WriteString(fh, "\n")
		if err != nil {
			return 0, err
		}
	}

	if err := fh.Close(); err != nil {
		return 0, err
	}

	return len(entries), nil
}

func generateAllRootsFiles(counterLog *writtenCounterLog) error {
	columns := inputCSVColumns{
		Subject:                             3,                                 // Column D
		SubjectHeaderName:                   "Common Name or Certificate Name", // Column D
		Owner:                               0,                                 // Column A
		OwnerHeaderName:                     "Owner",                           // Column A
		IssuerOrg:                           1,                                 // Column B
		IssuerOrgHeaderName:                 "Certificate Issuer Organization", // Column B
		PEM:                                 36,                                // Column AK
		PEMHeaderName:                       "PEM Info",                        // Column AK
		Hash:                                5,                                 // Column F
		HashHeaderName:                      "SHA-256 Fingerprint",             // Column F
		TrustBits:                           11,                                // Column L
		TrustBitsHeaderName:                 "Trust Bits",                      // Column L
		DistrustForTLSAfterDate:             12,                                // Column M
		DistrustForTLSAfterDateHeaderName:   "Distrust for TLS After Date",     // Column M
		DistrustForSMIMEAfterDate:           13,                                // Column N
		DistrustForSMIMEAfterDateHeaderName: "Distrust for S/MIME After Date",  // Column N
	}

	// This is the unfiltered collection. We'll created filtered collections
	// for Trust Bits specific output files.
	allEntries, err := generateRootCertEntries(
		csvOutputCACertsIncluded,
		columns,
		processingOptions{
			IgnoreDecodeErrors:    false,
			IgnoreParseErrors:     false,
			IgnoreEmptyEntries:    false,
			TrustBitFilterKeyword: "", // Doesn't apply here.
		},
	)

	if err != nil {
		return fmt.Errorf(
			"failed to generate root cert entries from input CSV file %s: %v",
			csvOutputCACertsIncluded,
			err,
		)
	}

	// All entries
	{
		log.Printf("Generating PEM file %q", pemOutputCACertsIncludedAll)

		pemWritten, err := generatePEMFile(
			allEntries,
			pemOutputCACertsIncludedAll,
			columns,
			processingOptions{
				IgnoreDecodeErrors:    false,
				IgnoreParseErrors:     false,
				IgnoreEmptyEntries:    false,
				TrustBitFilterKeyword: "", // Don't filter, get everything.
			},
		)
		if err != nil {
			return fmt.Errorf(
				"failed to generate PEM file %s from CSV file %s: %v",
				pemOutputCACertsIncludedAll,
				csvOutputCACertsIncluded,
				err,
			)
		}

		counterLog.CACertsIncludedAll = pemWritten

		log.Printf("Generating Hashes file %q", hashesOutputCACertsIncludedAll)

		hashesWritten, err := generateHashFile(
			csvOutputCACertsIncluded,
			hashesOutputCACertsIncludedAll,
			columns,
			processingOptions{
				IgnoreDecodeErrors:    false,
				IgnoreParseErrors:     false,
				IgnoreEmptyEntries:    false,
				TrustBitFilterKeyword: "", // Don't filter, get everything.
			},
		)
		if err != nil {
			return fmt.Errorf(
				"failed to generate Hashes file %s from CSV file %s: %v",
				hashesOutputCACertsIncludedAll,
				csvOutputCACertsIncluded,
				err,
			)
		}

		counterLog.CACertsIncludedHashesAll = hashesWritten
	}

	// Trust Bits: Websites
	{
		log.Printf("Generating PEM file %q", pemOutputCACertsIncludedWebsites)

		pemWritten, err := generatePEMFile(
			filterCertEntriesWithTLSTrustBitSet(allEntries),
			pemOutputCACertsIncludedWebsites,
			columns,
			processingOptions{
				IgnoreDecodeErrors:    false,
				IgnoreParseErrors:     false,
				IgnoreEmptyEntries:    false,
				TrustBitFilterKeyword: trustBitsKeywordWebsites,
			},
		)
		if err != nil {
			return fmt.Errorf(
				"failed to generate PEM file %s from CSV file %s: %v",
				pemOutputCACertsIncludedWebsites,
				csvOutputCACertsIncluded,
				err,
			)
		}

		counterLog.CACertsIncludedWebsites = pemWritten

		log.Printf("Generating Hashes file %q", hashesOutputCACertsIncludedWebsites)

		hashesWritten, err := generateHashFile(
			csvOutputCACertsIncluded,
			hashesOutputCACertsIncludedWebsites,
			columns,
			processingOptions{
				IgnoreDecodeErrors:    false,
				IgnoreParseErrors:     false,
				IgnoreEmptyEntries:    false,
				TrustBitFilterKeyword: trustBitsKeywordWebsites,
			},
		)
		if err != nil {
			return fmt.Errorf(
				"failed to generate Hashes file %s from CSV file %s: %v",
				hashesOutputCACertsIncludedWebsites,
				csvOutputCACertsIncluded,
				err,
			)
		}

		counterLog.CACertsIncludedHashesWebsites = hashesWritten
	}

	// Trust Bits: Email
	{
		log.Printf("Generating PEM file %q", pemOutputCACertsIncludedEmail)

		pemWritten, err := generatePEMFile(
			filterCertEntriesWithEmailTrustBitSet(allEntries),
			pemOutputCACertsIncludedEmail,
			columns,
			processingOptions{
				IgnoreDecodeErrors:    false,
				IgnoreParseErrors:     false,
				IgnoreEmptyEntries:    false,
				TrustBitFilterKeyword: trustBitsKeywordEmail,
			},
		)
		if err != nil {
			return fmt.Errorf(
				"failed to generate PEM file %s from CSV file %s: %v",
				pemOutputCACertsIncludedEmail,
				csvOutputCACertsIncluded,
				err,
			)
		}

		counterLog.CACertsIncludedEmail = pemWritten

		log.Printf("Generating Hashes file %q", hashesOutputCACertsIncludedEmail)

		hashesWritten, err := generateHashFile(
			csvOutputCACertsIncluded,
			hashesOutputCACertsIncludedEmail,
			columns,
			processingOptions{
				IgnoreDecodeErrors:    false,
				IgnoreParseErrors:     false,
				IgnoreEmptyEntries:    false,
				TrustBitFilterKeyword: trustBitsKeywordEmail,
			},
		)
		if err != nil {
			return fmt.Errorf(
				"failed to generate Hashes file %s from CSV file %s: %v",
				hashesOutputCACertsIncludedEmail,
				csvOutputCACertsIncluded,
				err,
			)
		}

		counterLog.CACertsIncludedHashesEmail = hashesWritten
	}

	return nil
}

func generateRemovedRootsFiles(counterLog *writtenCounterLog) error {
	log.Printf("Generating PEM file %q", pemOutputCACertsRemoved)

	columns := inputCSVColumns{
		Subject:             3,                                 // Column D
		SubjectHeaderName:   "Root Certificate Name",           // Column D
		Owner:               0,                                 // Column A
		OwnerHeaderName:     "Owner",                           // Column A
		IssuerOrg:           1,                                 // Column B
		IssuerOrgHeaderName: "Certificate Issuer Organization", // Column B
		PEM:                 21,                                // Column V
		PEMHeaderName:       "PEM Info",                        // Column V
		Hash:                7,                                 // Column H
		HashHeaderName:      "SHA-256 Fingerprint",             // Column H
		Comments:            20,                                // Column U
		CommentsHeaderName:  "Comments",                        // Column U
	}

	options := processingOptions{
		IgnoreDecodeErrors:    false,
		IgnoreParseErrors:     false,
		IgnoreEmptyEntries:    false,
		TrustBitFilterKeyword: "", // Don't filter, get everything.
	}

	// This is the unfiltered collection. We'll created filtered collections
	// for Trust Bits specific output files.
	allEntries, err := generateRootCertEntries(
		csvOutputCACertsRemoved,
		columns,
		options,
	)

	if err != nil {
		return fmt.Errorf(
			"failed to generate root cert entries from input CSV file %s: %v",
			csvOutputCACertsRemoved,
			err,
		)
	}

	pemWritten, err := generatePEMFile(
		allEntries,
		pemOutputCACertsRemoved,
		columns,
		options,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to generate PEM file %s from CSV file %s: %v",
			pemOutputCACertsRemoved,
			csvOutputCACertsRemoved,
			err,
		)
	}

	counterLog.CACertsRemoved = pemWritten

	log.Printf("Generating Hashes file %q", hashesOutputCACertsRemoved)

	hashesWritten, err := generateHashFile(
		csvOutputCACertsRemoved,
		hashesOutputCACertsRemoved,
		columns,
		options,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to generate Hashes file %s from CSV file %s: %v",
			hashesOutputCACertsRemoved,
			csvOutputCACertsRemoved,
			err,
		)
	}

	counterLog.CACertsRemovedHashes = hashesWritten

	return nil
}

func generateUpcomingRootRemovalsFiles(counterLog *writtenCounterLog) error {
	log.Printf("Generating PEM file %q", pemOutputCACertsUpcomingRemovals)

	columns := inputCSVColumns{
		Subject:             3,                                 // Column D
		SubjectHeaderName:   "Root Certificate Name",           // Column D
		Owner:               0,                                 // Column A
		OwnerHeaderName:     "Owner",                           // Column A
		IssuerOrg:           1,                                 // Column ?
		IssuerOrgHeaderName: "Certificate Issuer Organization", // Column ?
		PEM:                 19,                                // Column T
		PEMHeaderName:       "PEM Info",                        // Column T
		Hash:                6,                                 // Column G
		HashHeaderName:      "SHA-256 Fingerprint",             // Column G
		Comments:            18,                                // Column S
		CommentsHeaderName:  "Comments",                        // Column S
	}

	options := processingOptions{
		IgnoreDecodeErrors: false,
		IgnoreParseErrors:  false,

		// NOTE: This particular report has been observed to be
		// legitimately empty. We should not assert that entries are
		// present.
		IgnoreEmptyEntries: true,
	}

	allEntries, err := generateRootCertEntries(
		csvOutputCACertsUpcomingRemovals,
		columns,
		options,
	)

	if err != nil {
		return fmt.Errorf(
			"failed to generate root cert entries from input CSV file %s: %v",
			csvOutputCACertsUpcomingRemovals,
			err,
		)
	}

	pemWritten, err := generatePEMFile(
		allEntries,
		pemOutputCACertsUpcomingRemovals,
		columns,
		options,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to generate PEM file %s from CSV file %s: %v",
			pemOutputCACertsUpcomingRemovals,
			csvOutputCACertsUpcomingRemovals,
			err,
		)
	}

	counterLog.CACertsUpcomingRemovals = pemWritten

	log.Printf("Generating Hashes file %q", hashesOutputCACertsUpcomingRemovals)

	hashesWritten, err := generateHashFile(
		csvOutputCACertsUpcomingRemovals,
		hashesOutputCACertsUpcomingRemovals,
		columns,
		options,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to generate Hashes file %s from CSV file %s: %v",
			hashesOutputCACertsUpcomingRemovals,
			csvOutputCACertsUpcomingRemovals,
			err,
		)
	}

	counterLog.CACertsUpcomingRemovalsHashes = hashesWritten

	return nil
}

// generateHashFile evaluates the given input CSV file using the csvColumns
// value to locate applicable fields and saves the collected certificate
// hashes to the specified output file. If provided, hashes matching only the
// specified Trust Bits keyword are collected.
//
// NOTE: We reparse the input CSV file vs receiving a collection of
// rootCertEntry values in case there are parsing errors encountered (and
// skipped over).
// func generateHashFile(inputCSVFile string, outputTXTFile string, csvColumns inputCSVColumns, trustBitsFilterKeyword string) (int, error) {
func generateHashFile(inputCSVFile string, outputTXTFile string, csvColumns inputCSVColumns, options processingOptions) (int, error) {
	csvFile, err := os.Open(filepath.Clean(inputCSVFile))
	if err != nil {
		return 0, err
	}

	r := csv.NewReader(csvFile)
	header, err := r.Read()
	if err != nil {
		return 0, err
	}

	assertions := []columnHeaderAssertion{
		{
			InputFile:      inputCSVFile,
			ExpectedHeader: csvColumns.HashHeaderName,
			ActualHeader:   header[csvColumns.Hash],
			ColumnNum:      csvColumns.Hash,
		},
		{
			InputFile:      inputCSVFile,
			ExpectedHeader: csvColumns.TrustBitsHeaderName,
			ActualHeader:   header[csvColumns.TrustBits],
			ColumnNum:      csvColumns.TrustBits,
		},
	}

	if err := assertExpectedHeaderValues(assertions); err != nil {
		return 0, err
	}

	var hashes []string

	seen := make(map[string]bool)

	var lineCounter int

	for {
		lineCounter++

		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}

		record[csvColumns.Hash] = strings.Trim(record[csvColumns.Hash], "'")
		record[csvColumns.Hash] = strings.TrimSpace(record[csvColumns.Hash])

		if record[csvColumns.Hash] == "" {
			log.Printf("%#v", record)

			return 0, fmt.Errorf(
				"missing hash for entry %d for %s: %w",
				lineCounter,
				record[csvColumns.Subject],
				err,
			)
		}

		if seen[record[csvColumns.Hash]] {
			log.Printf("Duplicate record on line %d: %v", lineCounter, record[csvColumns.Subject])
			continue
		}
		seen[record[csvColumns.Hash]] = true

		switch {
		case options.TrustBitFilterKeyword == "":
			hashes = append(hashes, record[csvColumns.Hash])

		case strings.Contains(record[csvColumns.TrustBits], options.TrustBitFilterKeyword):
			hashes = append(hashes, record[csvColumns.Hash])

		default:
			continue
		}
	}

	if lineCounter == 0 && !options.IgnoreEmptyEntries {
		return 0, fmt.Errorf(
			"failed to parse input file %s: %w",
			inputCSVFile,
			ErrMissingEntries,
		)
	}

	// NOTE: This causes the hash entries to not have the same order as the
	// original CSV entries but does make for a cleaner diff between CA cert
	// changes.
	sort.Strings(hashes)

	fh, err := os.Create(filepath.Clean(outputTXTFile))
	if err != nil {
		return 0, err
	}

	defer func() {
		if err := fh.Close(); err != nil {
			// Ignore "file already closed" errors from our explicit file
			// close attempt at end of this function.
			if !errors.Is(err, os.ErrClosed) {
				log.Printf(
					"error occurred closing file %q: %v",
					outputTXTFile,
					err,
				)
			}
		}
	}()

	for _, hash := range hashes {
		_, err = io.WriteString(fh, hash+"\n")
		if err != nil {
			return 0, err
		}
	}

	if err := fh.Close(); err != nil {
		return 0, err
	}

	return len(hashes), nil
}

func getDistrustAfterDate(headerName string, fieldVal string, dateLayout string) (time.Time, error) {
	var distrustAfterDate time.Time

	if headerName == "" {
		return time.Time{}, nil
	}

	fieldVal = strings.TrimSpace(fieldVal)

	if fieldVal != "" {
		var err error

		distrustAfterDate, err = time.Parse(dateLayout, fieldVal)

		if err != nil {
			return time.Time{}, err
		}
	}

	return distrustAfterDate, nil
}

func writeCounterLog(outputFile string, counterLog writtenCounterLog) error {
	fh, err := os.Create(filepath.Clean(outputFile))
	if err != nil {
		return err
	}

	defer func() {
		if err := fh.Close(); err != nil {
			// Ignore "file already closed" errors from our explicit file
			// close attempt at end of this function.
			if !errors.Is(err, os.ErrClosed) {
				log.Printf(
					"error occurred closing file %q: %v",
					outputFile,
					err,
				)
			}
		}
	}()

	if err := tmpl.Execute(fh, counterLog); err != nil {
		return err
	}

	return fh.Close()
}

func filterCertEntriesWithTLSTrustBitSet(entries []rootCertEntry) []rootCertEntry {
	results := make([]rootCertEntry, 0, len(entries))

	for _, cert := range entries {
		if cert.TrustBitTLS {
			results = append(results, cert)
		}
	}

	return results
}

func filterCertEntriesWithEmailTrustBitSet(entries []rootCertEntry) []rootCertEntry {
	results := make([]rootCertEntry, 0, len(entries))

	for _, cert := range entries {
		if cert.TrustBitEmail {
			results = append(results, cert)
		}
	}

	return results
}

func assertExpectedHeaderValues(assertions []columnHeaderAssertion) error {
	for _, assertion := range assertions {
		if assertion.ExpectedHeader == "" {
			continue
		}

		if assertion.ActualHeader != assertion.ExpectedHeader {
			return fmt.Errorf(
				"unexpected input file format: CSV file %s column %d"+
					" (zero-based) does not contain %q",
				assertion.InputFile,
				assertion.ColumnNum,
				assertion.ExpectedHeader,
			)
		}

	}

	return nil
}

var tmpl = template.Must(template.New("count.go").Parse(
	`// Code generated by generate.go. DO NOT EDIT.

package roots

const (
	expectedCountCACertsIncludedAll            = {{ .CACertsIncludedAll }}
	expectedCountCACertsIncludedWebsites       = {{ .CACertsIncludedWebsites }}
	expectedCountCACertsIncludedEmail          = {{ .CACertsIncludedEmail }}
	expectedCountCACertsIncludedHashesAll      = {{ .CACertsIncludedHashesAll }}
	expectedCountCACertsIncludedHashesWebsites = {{ .CACertsIncludedHashesWebsites }}
	expectedCountCACertsIncludedHashesEmail    = {{ .CACertsIncludedHashesEmail }}
	expectedCountCACertsRemoved                = {{ .CACertsRemoved }}
	expectedCountCACertsRemovedHashes          = {{ .CACertsRemovedHashes }}
	expectedCountCACertsUpcomingRemovals       = {{ .CACertsUpcomingRemovals }}
	expectedCountCACertsUpcomingRemovalsHashes = {{ .CACertsUpcomingRemovalsHashes }}
)
`))
