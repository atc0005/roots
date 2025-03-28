// Copyright 2021 Google LLC
// Copyright 2025 Adam Chalkley
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package roots

import (
	"crypto/x509"
	"testing"
)

func TestCertsRetrievalCounts(t *testing.T) {
	testFunc := func(t *testing.T, fn func() []*x509.Certificate, expectedCount int) {
		if gotCount := len(fn()); gotCount != expectedCount {
			t.Errorf("roots: failed to load all certificates; got %d certificates, wanted %d", gotCount, expectedCount)
		} else {
			t.Logf("roots: successfully loaded %d of %d certificates", gotCount, expectedCount)
		}
	}

	testFunc(t, MustGetIncludedAllCACerts, expectedCountCACertsIncludedAll)
	testFunc(t, MustGetIncludedCACertsTrustBitWebsites, expectedCountCACertsIncludedWebsites)
	testFunc(t, MustGetIncludedCACertsTrustBitEmail, expectedCountCACertsIncludedEmail)
	testFunc(t, MustGetRemovedCACerts, expectedCountCACertsRemoved)
	testFunc(t, MustGetUpcomingRemovalsCACerts, expectedCountCACertsUpcomingRemovals)

}

func TestCertsHashesRetrievalCounts(t *testing.T) {
	testFunc := func(t *testing.T, fn func() []string, expectedCount int) {
		if gotCount := len(fn()); gotCount != expectedCount {
			t.Errorf("roots: failed to load all certificate hashes; got %d hashes, wanted %d", gotCount, expectedCount)
		} else {
			t.Logf("roots: successfully loaded %d of %d certificate hashes", gotCount, expectedCount)
		}
	}

	testFunc(t, MustGetIncludedAllCACertsHashes, expectedCountCACertsIncludedHashesAll)
	testFunc(t, MustGetIncludedCACertsTrustBitWebsitesHashes, expectedCountCACertsIncludedHashesWebsites)
	testFunc(t, MustGetIncludedCACertsTrustBitEmailHashes, expectedCountCACertsIncludedHashesEmail)
	testFunc(t, MustGetRemovedCACertsHashes, expectedCountCACertsRemovedHashes)
	testFunc(t, MustGetUpcomingRemovalsCACertsHashes, expectedCountCACertsUpcomingRemovalsHashes)

}

func TestCertsRetrievalFromGetFuncs(t *testing.T) {
	testFunc := func(t *testing.T, fn func() ([]*x509.Certificate, error), funcDescription string) {
		if certs, err := fn(); err != nil {
			t.Fatalf("roots: failed to load certificates via %s func: %v", funcDescription, err)
		} else {
			t.Logf("roots: successfully loaded %d certificates via %s func.", len(certs), funcDescription)
		}
	}

	testFunc(t, GetIncludedAllCACerts, "GetIncludedAllCACerts")
	testFunc(t, GetIncludedCACertsTrustBitWebsites, "GetIncludedCACertsTrustBitWebsites")
	testFunc(t, GetIncludedCACertsTrustBitEmail, "GetIncludedCACertsTrustBitEmail")
	testFunc(t, GetRemovedCACerts, "GetRemovedCACerts")
	testFunc(t, GetUpcomingRemovalsCACerts, "GetUpcomingRemovalsCACerts")

}

func TestCertsRetrievalFromMustGetFuncs(t *testing.T) {
	testFunc := func(t *testing.T, fn func() []*x509.Certificate, funcDescription string) {
		certs := fn()
		t.Logf("successfully loaded %d certificates via %s func.", len(certs), funcDescription)
	}

	testFunc(t, MustGetIncludedAllCACerts, "MustGetIncludedAllCACerts")
	testFunc(t, MustGetIncludedCACertsTrustBitWebsites, "MustGetIncludedCACertsTrustBitWebsites")
	testFunc(t, MustGetIncludedCACertsTrustBitEmail, "MustGetIncludedCACertsTrustBitEmail")
	testFunc(t, MustGetRemovedCACerts, "MustGetRemovedCACerts")
	testFunc(t, MustGetUpcomingRemovalsCACerts, "MustGetUpcomingRemovalsCACerts")
}

func TestCertsHashesRetrievalFromGetFuncs(t *testing.T) {
	testFunc := func(t *testing.T, fn func() ([]string, error), funcDescription string) {
		if certs, err := fn(); err != nil {
			t.Fatalf("roots: failed to load certificate hashes via %s func: %v", funcDescription, err)
		} else {
			t.Logf("roots: successfully loaded %d certificate hashes via %s func.", len(certs), funcDescription)
		}
	}

	testFunc(t, GetIncludedAllCACertsHashes, "GetIncludedAllCACertsHashes")
	testFunc(t, GetIncludedCACertsTrustBitWebsitesHashes, "GetIncludedCACertsTrustBitWebsitesHashes")
	testFunc(t, GetIncludedCACertsTrustBitEmailHashes, "GetIncludedCACertsTrustBitEmailHashes")
	testFunc(t, GetRemovedCACertsHashes, "GetRemovedCACertsHashes")
	testFunc(t, GetUpcomingRemovalsCACertsHashes, "GetUpcomingRemovalsCACertsHashes")
}

func TestCertsHashesRetrievalFromMustGetFuncs(t *testing.T) {
	testFunc := func(t *testing.T, fn func() []string, funcDescription string) {
		certs := fn()
		t.Logf("roots: successfully loaded %d certificate hashes via %s func.", len(certs), funcDescription)
	}

	testFunc(t, MustGetIncludedAllCACertsHashes, "MustGetIncludedAllCACertsHashes")
	testFunc(t, MustGetIncludedCACertsTrustBitWebsitesHashes, "MustGetIncludedCACertsTrustBitWebsitesHashes")
	testFunc(t, MustGetIncludedCACertsTrustBitEmailHashes, "MustGetIncludedCACertsTrustBitEmailHashes")
	testFunc(t, MustGetRemovedCACertsHashes, "MustGetRemovedCACertsHashes")
	testFunc(t, MustGetUpcomingRemovalsCACertsHashes, "MustGetUpcomingRemovalsCACertsHashes")
}
