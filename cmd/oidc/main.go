/*
Copyright 2021 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

func extractIssuer(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("oidc: malformed jwt, expected 3 parts got %d", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("oidc: malformed jwt payload: %w", err)
	}
	var payload struct {
		Issuer string `json:"iss"`
	}

	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", fmt.Errorf("oidc: failed to unmarshal claims: %w", err)
	}
	return payload.Issuer, nil
}

func main() {
	path := "/var/run/kind-oidc/token"

	auth, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Unable to read %q: %v", path, err)
	}

	issuer, err := extractIssuer(string(auth))
	if err != nil {
		log.Fatalf("Unable to extract issuer: %v", err)
	}

	// Verify the token before we trust anything about it.
	provider, err := oidc.NewProvider(context.Background(), issuer)
	if err != nil {
		log.Fatalf("Unable to instantiate OIDC provider: %v", err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: "kind-oidc"})
	_, err = verifier.Verify(context.Background(), string(auth))
	if err != nil {
		log.Fatalf("Unable to verify OIDC token: %v", err)
	}

	log.Print("OIDC token verified!")
}
