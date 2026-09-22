// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/localca"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// A release hook reruns on every upgrade. It must never replace existing key
// material, and must not fail because the material already exists.
func TestCreatePoolSecretIfAbsentKeepsExistingKeys(t *testing.T) {
	ctx := t.Context()
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ate-system", Name: "actor-id-jwt-pool"},
		Data:       map[string][]byte{"pool": []byte("original")},
	}
	kc := fake.NewClientset(existing)

	replacement := existing.DeepCopy()
	replacement.Data["pool"] = []byte("replacement")
	if err := createPoolSecret(ctx, kc, replacement, true); err != nil {
		t.Fatalf("createPoolSecret(ifAbsent) on existing secret: %v", err)
	}
	got, err := kc.CoreV1().Secrets("ate-system").Get(ctx, "actor-id-jwt-pool", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data["pool"]) != "original" {
		t.Errorf("pool = %q, want the original key material kept", got.Data["pool"])
	}
	if err := createPoolSecret(ctx, kc, replacement, false); err == nil {
		t.Error("createPoolSecret without ifAbsent succeeded on an existing secret, want an error")
	}
}

func TestCACertsSecretPublishesPoolTrustAnchors(t *testing.T) {
	ca, err := localca.GenerateCA("1", localca.KeyTypeED25519, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	poolBytes, err := localca.Marshal(&localca.ConcretePool{CAs: []*localca.CA{ca}, ActiveForSigning: "1"})
	if err != nil {
		t.Fatal(err)
	}
	pool := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ate-system", Name: "actor-id-ca-pool"},
		Data:       map[string][]byte{"pool": poolBytes, corev1.TLSPrivateKeyKey: []byte("private")},
	}

	got, err := caCertsSecret(pool, "ate-system", "actor-id-ca-certs")
	if err != nil {
		t.Fatalf("caCertsSecret: %v", err)
	}
	if _, ok := got.Data[corev1.TLSPrivateKeyKey]; ok || len(got.Data) != 1 {
		t.Fatalf("published keys = %v, want only ca.crt", got.Data)
	}
	block, rest := pem.Decode(got.Data["ca.crt"])
	if block == nil || len(rest) != 0 {
		t.Fatalf("ca.crt is not exactly one PEM certificate: %q", got.Data["ca.crt"])
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.Equal(ca.RootCertificate) {
		t.Error("ca.crt does not hold the pool's root certificate")
	}
}
