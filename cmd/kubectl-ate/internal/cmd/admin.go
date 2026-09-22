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
	"context"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/agent-substrate/substrate/internal/ateclient"
	"github.com/agent-substrate/substrate/internal/localca"
	"github.com/agent-substrate/substrate/internal/localjwtauthority"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var (
	// Both pool commands write one secret, so they share the flags naming it.
	poolSecretNamespaceFlag string
	poolSecretNameFlag      string
	makeCaPoolIDFlag        string
	makeCaPoolKeyTypeFlag   string
	makeJwtPoolKeyIDFlag    string
	poolIfAbsentFlag        bool
	caCertsFromPoolFlag     string
)

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Administration and debugging commands",
}

var makeCaPoolCmd = &cobra.Command{
	Use:   "make-ca-pool",
	Short: "Make a new secret that contains a CA pool to be used by a signing controller",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		kconfig, err := ateclient.LoadKubeConfig(kubeconfig, k8sContext)
		if err != nil {
			return fmt.Errorf("while reading kubeconfig: %w", err)
		}

		kc, err := kubernetes.NewForConfig(kconfig)
		if err != nil {
			return fmt.Errorf("while creating Kubernetes client: %w", err)
		}

		var keyType localca.KeyType
		switch makeCaPoolKeyTypeFlag {
		case "ED25519":
			keyType = localca.KeyTypeED25519
		case "ECDSAP256":
			keyType = localca.KeyTypeECDSAP256
		default:
			return fmt.Errorf("unknown key type %q", makeCaPoolKeyTypeFlag)
		}

		ca, err := localca.GenerateCA(
			makeCaPoolIDFlag,
			keyType,
			365*24*time.Hour,
		)
		if err != nil {
			return fmt.Errorf("while generating CA: %w", err)
		}

		pool := &localca.ConcretePool{
			CAs:              []*localca.CA{ca},
			ActiveForSigning: makeCaPoolIDFlag,
		}

		poolBytes, err := localca.Marshal(pool)
		if err != nil {
			return fmt.Errorf("while marshaling pool: %w", err)
		}
		certificateChain, err := ca.TLSCertificateChainPEM()
		if err != nil {
			return fmt.Errorf("while encoding CA certificate chain: %w", err)
		}
		privateKey, err := ca.TLSPrivateKeyPEM()
		if err != nil {
			return fmt.Errorf("while encoding CA private key: %w", err)
		}

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: poolSecretNamespaceFlag,
				Name:      poolSecretNameFlag,
			},
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{
				"pool":                  poolBytes,
				corev1.TLSCertKey:       certificateChain,
				corev1.TLSPrivateKeyKey: privateKey,
			},
		}

		return createPoolSecret(ctx, kc, secret, poolIfAbsentFlag)
	},
}

var makeJwtPoolCmd = &cobra.Command{
	Use:   "make-jwt-pool",
	Short: "Make a new secret that contains a JWT authority pool to be used by the actor ID broker",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		kconfig, err := ateclient.LoadKubeConfig(kubeconfig, k8sContext)
		if err != nil {
			return fmt.Errorf("while reading kubeconfig: %w", err)
		}

		kc, err := kubernetes.NewForConfig(kconfig)
		if err != nil {
			return fmt.Errorf("while creating Kubernetes client: %w", err)
		}

		authority, err := localjwtauthority.GenerateECDSAP256Authority(makeJwtPoolKeyIDFlag)
		if err != nil {
			return fmt.Errorf("while generating JWT authority: %w", err)
		}

		pool := &localjwtauthority.ConcretePool{
			Authorities:      []*localjwtauthority.Authority{authority},
			ActiveForSigning: makeJwtPoolKeyIDFlag,
		}

		poolBytes, err := localjwtauthority.Marshal(pool)
		if err != nil {
			return fmt.Errorf("while marshaling pool: %w", err)
		}

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: poolSecretNamespaceFlag,
				Name:      poolSecretNameFlag,
			},
			Data: map[string][]byte{
				"pool": poolBytes,
			},
		}

		return createPoolSecret(ctx, kc, secret, poolIfAbsentFlag)
	},
}

var makeCACertsCmd = &cobra.Command{
	Use:   "make-ca-certs",
	Short: "Make a secret that publishes the trust anchors of an existing CA pool secret, without its keys",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		kconfig, err := ateclient.LoadKubeConfig(kubeconfig, k8sContext)
		if err != nil {
			return fmt.Errorf("while reading kubeconfig: %w", err)
		}

		kc, err := kubernetes.NewForConfig(kconfig)
		if err != nil {
			return fmt.Errorf("while creating Kubernetes client: %w", err)
		}

		pool, err := kc.CoreV1().Secrets(poolSecretNamespaceFlag).Get(ctx, caCertsFromPoolFlag, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("while reading CA pool secret %s/%s: %w", poolSecretNamespaceFlag, caCertsFromPoolFlag, err)
		}
		secret, err := caCertsSecret(pool, poolSecretNamespaceFlag, poolSecretNameFlag)
		if err != nil {
			return err
		}
		return createPoolSecret(ctx, kc, secret, poolIfAbsentFlag)
	},
}

// createPoolSecret creates secret. With ifAbsent an existing secret of the same
// name is kept unchanged and counts as success, so a release hook can rerun
// without replacing issued key material.
func createPoolSecret(ctx context.Context, kc kubernetes.Interface, secret *corev1.Secret, ifAbsent bool) error {
	_, err := kc.CoreV1().Secrets(secret.Namespace).Create(ctx, secret, metav1.CreateOptions{})
	switch {
	case err == nil:
		fmt.Printf("Successfully created secret %s/%s\n", secret.Namespace, secret.Name)
		return nil
	case ifAbsent && apierrors.IsAlreadyExists(err):
		fmt.Printf("Secret %s/%s already exists; keeping it\n", secret.Namespace, secret.Name)
		return nil
	default:
		return fmt.Errorf("while creating secret %s/%s: %w", secret.Namespace, secret.Name, err)
	}
}

// caCertsSecret derives a secret holding only the PEM trust anchors of the CA
// pool stored in pool, for consumers that must verify but never sign.
func caCertsSecret(pool *corev1.Secret, namespace, name string) (*corev1.Secret, error) {
	concrete, err := localca.Unmarshal(pool.Data["pool"])
	if err != nil {
		return nil, fmt.Errorf("while parsing CA pool secret %s/%s: %w", pool.Namespace, pool.Name, err)
	}
	anchors, err := concrete.TrustAnchors()
	if err != nil {
		return nil, fmt.Errorf("while reading trust anchors of %s/%s: %w", pool.Namespace, pool.Name, err)
	}
	if len(anchors) == 0 {
		return nil, fmt.Errorf("CA pool secret %s/%s has no trust anchors", pool.Namespace, pool.Name)
	}
	var bundle []byte
	for _, cert := range anchors {
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Data:       map[string][]byte{"ca.crt": bundle},
	}, nil
}

func init() {
	rootCmd.AddCommand(adminCmd)

	makeCaPoolCmd.Flags().StringVar(&makeCaPoolIDFlag, "ca-id", "", "The ID of the initial CA in the Pool")
	makeCaPoolCmd.Flags().StringVar(&poolSecretNamespaceFlag, "secret-namespace", "default", "Create the secret in this namespace")
	makeCaPoolCmd.Flags().StringVar(&poolSecretNameFlag, "name", "", "Create the secret with this name")
	makeCaPoolCmd.Flags().StringVar(&makeCaPoolKeyTypeFlag, "key-type", "ED25519", "CA key type.  One of [ED25519, ECDSAP256]")
	_ = makeCaPoolCmd.MarkFlagRequired("name")
	adminCmd.AddCommand(makeCaPoolCmd)

	makeJwtPoolCmd.Flags().StringVar(&makeJwtPoolKeyIDFlag, "key-id", "1", "The ID of the initial JWT signing key in the pool")
	makeJwtPoolCmd.Flags().StringVar(&poolSecretNamespaceFlag, "secret-namespace", "default", "Create the secret in this namespace")
	makeJwtPoolCmd.Flags().StringVar(&poolSecretNameFlag, "name", "", "Create the secret with this name")
	_ = makeJwtPoolCmd.MarkFlagRequired("name")
	adminCmd.AddCommand(makeJwtPoolCmd)

	makeCACertsCmd.Flags().StringVar(&caCertsFromPoolFlag, "from-pool", "", "Name of the CA pool secret whose trust anchors to publish")
	makeCACertsCmd.Flags().StringVar(&poolSecretNamespaceFlag, "secret-namespace", "default", "Namespace of both the pool secret and the created secret")
	makeCACertsCmd.Flags().StringVar(&poolSecretNameFlag, "name", "", "Create the secret with this name")
	_ = makeCACertsCmd.MarkFlagRequired("from-pool")
	_ = makeCACertsCmd.MarkFlagRequired("name")
	adminCmd.AddCommand(makeCACertsCmd)

	for _, c := range []*cobra.Command{makeCaPoolCmd, makeJwtPoolCmd, makeCACertsCmd} {
		c.Flags().BoolVar(&poolIfAbsentFlag, "if-absent", false, "Keep an existing secret of the same name unchanged instead of failing")
	}
}
