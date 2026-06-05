package db

import "testing"

func TestShouldSkipTechnologyObservationSkipsGenericUnversionedNoise(t *testing.T) {
	obs := TechnologyObservation{
		Name:   " Amazon   CloudFront ",
		Source: "webanalyze",
	}

	if !shouldSkipTechnologyObservation(obs) {
		t.Fatal("generic unversioned infrastructure technology should be skipped")
	}
}

func TestShouldSkipTechnologyObservationKeepsVersionedTechnology(t *testing.T) {
	obs := TechnologyObservation{
		Name:    "Amazon CloudFront",
		Version: "2026.1",
		Source:  "webanalyze",
	}

	if shouldSkipTechnologyObservation(obs) {
		t.Fatal("versioned technology should be persisted")
	}
}

func TestShouldSkipTechnologyObservationKeepsSpecificUnversionedTechnology(t *testing.T) {
	obs := TechnologyObservation{
		Name:   "Apache ActiveMQ",
		Source: "webanalyze",
	}

	if shouldSkipTechnologyObservation(obs) {
		t.Fatal("specific unversioned technology should be persisted")
	}
}
