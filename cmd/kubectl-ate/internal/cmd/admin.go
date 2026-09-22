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
	"io"
	"text/tabwriter"
	"time"

	"github.com/agent-substrate/substrate/internal/ateclient"
	"github.com/agent-substrate/substrate/internal/localca"
	"github.com/agent-substrate/substrate/internal/localjwtauthority"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/util/retry"
)

var (
	// Each pool command writes one secret, so they share the flags naming it.
	poolSecretNamespaceFlag string
	poolSecretNameFlag      string
	makeCaPoolIDFlag        string
	makeCaPoolKeyTypeFlag   string
	makeCaPoolValidityFlag  time.Duration
	jwtAlgFlag              string
	jwtKeyIDFlag            string
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

		kc, err := newKubeClient()
		if err != nil {
			return err
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
			makeCaPoolValidityFlag,
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

		_, err = createPoolSecret(ctx, kc, secret, poolIfAbsentFlag)
		return err
	},
}

var makeJwtPoolCmd = &cobra.Command{
	Use:   "make-jwt-pool",
	Short: "Make a new secret that contains a JWT authority pool to be used by the actor ID broker",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		kc, err := newKubeClient()
		if err != nil {
			return err
		}

		secret, keyID, err := newJWTPoolSecret(poolSecretNamespaceFlag, poolSecretNameFlag, jwtAlgFlag, jwtKeyIDFlag)
		if err != nil {
			return err
		}

		created, err := createPoolSecret(ctx, kc, secret, poolIfAbsentFlag)
		if err != nil {
			return err
		}
		if created {
			fmt.Printf("Created JWT authority pool secret %s/%s with %s key %s\n", poolSecretNamespaceFlag, poolSecretNameFlag, jwtAlgFlag, keyID)
		}
		return nil
	},
}

var makeCACertsCmd = &cobra.Command{
	Use:   "make-ca-certs",
	Short: "Make a secret that publishes the trust anchors of an existing CA pool secret, without its keys",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		kc, err := newKubeClient()
		if err != nil {
			return err
		}

		pool, err := kc.CoreV1().Secrets(poolSecretNamespaceFlag).Get(ctx, caCertsFromPoolFlag, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("while reading CA pool secret %s/%s: %w", poolSecretNamespaceFlag, caCertsFromPoolFlag, err)
		}
		secret, err := caCertsSecret(pool, poolSecretNamespaceFlag, poolSecretNameFlag)
		if err != nil {
			return err
		}
		_, err = createPoolSecret(ctx, kc, secret, poolIfAbsentFlag)
		return err
	},
}

// createPoolSecret creates secret and reports whether it did. With ifAbsent an
// existing secret of the same name is kept unchanged and counts as success, so
// a release hook can rerun without replacing issued key material.
func createPoolSecret(ctx context.Context, kc kubernetes.Interface, secret *corev1.Secret, ifAbsent bool) (bool, error) {
	_, err := kc.CoreV1().Secrets(secret.Namespace).Create(ctx, secret, metav1.CreateOptions{})
	switch {
	case err == nil:
		fmt.Printf("Successfully created secret %s/%s\n", secret.Namespace, secret.Name)
		return true, nil
	case ifAbsent && apierrors.IsAlreadyExists(err):
		fmt.Printf("Secret %s/%s already exists; keeping it\n", secret.Namespace, secret.Name)
		return false, nil
	default:
		return false, fmt.Errorf("while creating secret %s/%s: %w", secret.Namespace, secret.Name, err)
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

var listJwtKeysCmd = &cobra.Command{
	Use:   "list-jwt-keys",
	Short: "List the keys in a JWT authority pool secret",
	RunE: func(cmd *cobra.Command, args []string) error {
		kc, err := newKubeClient()
		if err != nil {
			return err
		}

		_, pool, err := getJWTPool(cmd.Context(), kc.CoreV1().Secrets(poolSecretNamespaceFlag), poolSecretNameFlag)
		if err != nil {
			return err
		}
		return printJWTKeys(cmd.OutOrStdout(), pool)
	},
}

var addJwtKeyCmd = &cobra.Command{
	Use:   "add-jwt-key",
	Short: "Add an inactive signing key to a JWT authority pool secret",
	Long: `Add an inactive signing key to a JWT authority pool secret.

The key is published to relying parties but signs nothing until activate-jwt-key
makes it the signing key. Activate it only once relying parties have refetched
the key set.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		kc, err := newKubeClient()
		if err != nil {
			return err
		}

		authority, err := localjwtauthority.GenerateAuthority(jwtAlgFlag, jwtKeyIDFlag)
		if err != nil {
			return fmt.Errorf("while generating JWT authority: %w", err)
		}
		if err := updateJWTPool(cmd.Context(), kc.CoreV1().Secrets(poolSecretNamespaceFlag), poolSecretNameFlag, func(pool *localjwtauthority.ConcretePool) error {
			return pool.AddAuthority(authority)
		}); err != nil {
			return err
		}

		fmt.Printf("Added inactive %s key %s to JWT authority pool secret %s/%s\n", jwtAlgFlag, authority.ID, poolSecretNamespaceFlag, poolSecretNameFlag)
		return nil
	},
}

var activateJwtKeyCmd = &cobra.Command{
	Use:   "activate-jwt-key",
	Short: "Make a key in a JWT authority pool secret the one that signs",
	RunE: func(cmd *cobra.Command, args []string) error {
		kc, err := newKubeClient()
		if err != nil {
			return err
		}

		if err := updateJWTPool(cmd.Context(), kc.CoreV1().Secrets(poolSecretNamespaceFlag), poolSecretNameFlag, func(pool *localjwtauthority.ConcretePool) error {
			return pool.Activate(jwtKeyIDFlag)
		}); err != nil {
			return err
		}

		fmt.Printf("Activated key %s in JWT authority pool secret %s/%s\n", jwtKeyIDFlag, poolSecretNamespaceFlag, poolSecretNameFlag)
		return nil
	},
}

var removeJwtKeyCmd = &cobra.Command{
	Use:   "remove-jwt-key",
	Short: "Remove an inactive key from a JWT authority pool secret",
	Long: `Remove an inactive key from a JWT authority pool secret.

Tokens the key signed stop verifying once relying parties refetch the key set,
so remove it only after the last of them has expired.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		kc, err := newKubeClient()
		if err != nil {
			return err
		}

		if err := updateJWTPool(cmd.Context(), kc.CoreV1().Secrets(poolSecretNamespaceFlag), poolSecretNameFlag, func(pool *localjwtauthority.ConcretePool) error {
			return pool.RemoveAuthority(jwtKeyIDFlag)
		}); err != nil {
			return err
		}

		fmt.Printf("Removed key %s from JWT authority pool secret %s/%s\n", jwtKeyIDFlag, poolSecretNamespaceFlag, poolSecretNameFlag)
		return nil
	},
}

// updateJWTPool applies change to the pool in the named secret and writes it
// back. The write is conditional on the secret's resourceVersion, and a
// conflict reruns change against the current pool.
func updateJWTPool(ctx context.Context, secrets typedcorev1.SecretInterface, name string, change func(*localjwtauthority.ConcretePool) error) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		secret, pool, err := getJWTPool(ctx, secrets, name)
		if err != nil {
			return err
		}

		if err := change(pool); err != nil {
			return err
		}

		wire, err := localjwtauthority.Marshal(pool)
		if err != nil {
			return fmt.Errorf("while marshaling pool: %w", err)
		}
		secret.Data["pool"] = wire
		if _, err := secrets.Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("while writing pool secret: %w", err)
		}
		return nil
	})
}

// getJWTPool reads the named secret and parses the pool it holds.
func getJWTPool(ctx context.Context, secrets typedcorev1.SecretInterface, name string) (*corev1.Secret, *localjwtauthority.ConcretePool, error) {
	secret, err := secrets.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("while reading pool secret: %w", err)
	}
	wire, ok := secret.Data["pool"]
	if !ok {
		return nil, nil, fmt.Errorf("secret %s/%s has no \"pool\" key", secret.Namespace, secret.Name)
	}
	pool, err := localjwtauthority.Unmarshal(wire)
	if err != nil {
		return nil, nil, fmt.Errorf("while parsing pool: %w", err)
	}
	return secret, pool, nil
}

// printJWTKeys prints the ID and algorithm of every key in the pool, marking
// the one that signs. It prints nothing about the private keys.
func printJWTKeys(out io.Writer, pool *localjwtauthority.ConcretePool) error {
	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ACTIVE\tKEY ID\tALGORITHM")
	for _, authority := range pool.Authorities {
		active := ""
		if authority.ID == pool.ActiveID() {
			active = "*"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", active, authority.ID, authority.Algorithm)
	}
	return w.Flush()
}

// newKubeClient builds a client from the --kubeconfig and --context flags.
func newKubeClient() (kubernetes.Interface, error) {
	kconfig, err := ateclient.LoadKubeConfig(kubeconfig, k8sContext)
	if err != nil {
		return nil, fmt.Errorf("while reading kubeconfig: %w", err)
	}
	kc, err := kubernetes.NewForConfig(kconfig)
	if err != nil {
		return nil, fmt.Errorf("while creating Kubernetes client: %w", err)
	}
	return kc, nil
}

// newJWTPoolSecret builds a Secret holding a pool with one active authority,
// and returns the authority's key ID.
func newJWTPoolSecret(namespace, name, algorithm, keyID string) (*corev1.Secret, string, error) {
	poolBytes, id, err := localjwtauthority.GeneratePool(algorithm, keyID)
	if err != nil {
		return nil, "", fmt.Errorf("while generating JWT authority pool: %w", err)
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Data: map[string][]byte{
			"pool": poolBytes,
		},
	}, id, nil
}

func init() {
	rootCmd.AddCommand(adminCmd)

	makeCaPoolCmd.Flags().StringVar(&makeCaPoolIDFlag, "ca-id", "", "The ID of the initial CA in the Pool")
	makeCaPoolCmd.Flags().StringVar(&poolSecretNamespaceFlag, "secret-namespace", "default", "Create the secret in this namespace")
	makeCaPoolCmd.Flags().StringVar(&poolSecretNameFlag, "name", "", "Create the secret with this name")
	makeCaPoolCmd.Flags().StringVar(&makeCaPoolKeyTypeFlag, "key-type", "ED25519", "CA key type.  One of [ED25519, ECDSAP256]")
	makeCaPoolCmd.Flags().DurationVar(&makeCaPoolValidityFlag, "validity", 365*24*time.Hour, "How long the CA certificate is valid for")
	_ = makeCaPoolCmd.MarkFlagRequired("name")
	adminCmd.AddCommand(makeCaPoolCmd)

	makeJwtPoolCmd.Flags().StringVar(&jwtAlgFlag, "alg", "ES256", "Signing algorithm of the initial key.  One of [ES256, RS256]; RS256 keys are 4096-bit RSA")
	makeJwtPoolCmd.Flags().StringVar(&jwtKeyIDFlag, "key-id", "", "The ID of the initial JWT signing key in the pool.  Defaults to the base64url SHA-256 of the key's PKIX encoding")
	makeJwtPoolCmd.Flags().StringVar(&poolSecretNamespaceFlag, "secret-namespace", "default", "Create the secret in this namespace")
	makeJwtPoolCmd.Flags().StringVar(&poolSecretNameFlag, "name", "", "Create the secret with this name")
	_ = makeJwtPoolCmd.MarkFlagRequired("name")
	adminCmd.AddCommand(makeJwtPoolCmd)

	listJwtKeysCmd.Flags().StringVar(&poolSecretNamespaceFlag, "secret-namespace", "default", "The namespace of the pool secret")
	listJwtKeysCmd.Flags().StringVar(&poolSecretNameFlag, "name", "", "The name of the pool secret")
	_ = listJwtKeysCmd.MarkFlagRequired("name")
	adminCmd.AddCommand(listJwtKeysCmd)

	addJwtKeyCmd.Flags().StringVar(&jwtAlgFlag, "alg", "ES256", "Signing algorithm of the new key.  One of [ES256, RS256]; RS256 keys are 4096-bit RSA")
	addJwtKeyCmd.Flags().StringVar(&jwtKeyIDFlag, "key-id", "", "The ID of the new key.  Defaults to the base64url SHA-256 of the key's PKIX encoding")
	addJwtKeyCmd.Flags().StringVar(&poolSecretNamespaceFlag, "secret-namespace", "default", "The namespace of the pool secret")
	addJwtKeyCmd.Flags().StringVar(&poolSecretNameFlag, "name", "", "The name of the pool secret")
	_ = addJwtKeyCmd.MarkFlagRequired("name")
	adminCmd.AddCommand(addJwtKeyCmd)

	for _, cmd := range []*cobra.Command{activateJwtKeyCmd, removeJwtKeyCmd} {
		cmd.Flags().StringVar(&jwtKeyIDFlag, "key-id", "", "The ID of the key")
		cmd.Flags().StringVar(&poolSecretNamespaceFlag, "secret-namespace", "default", "The namespace of the pool secret")
		cmd.Flags().StringVar(&poolSecretNameFlag, "name", "", "The name of the pool secret")
		_ = cmd.MarkFlagRequired("key-id")
		_ = cmd.MarkFlagRequired("name")
		adminCmd.AddCommand(cmd)
	}

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
