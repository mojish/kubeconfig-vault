package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"slices"
	"time"
)

// An encrypted record carries the PEM required by the Kubernetes exec API.
// Kubeconfig inputs and portable exports use the base64-encoded data fields.
type clientCertificate struct {
	CertPEM   string `json:"cert_pem"`
	KeyPEM    string `json:"key_pem"`
	NotBefore int64  `json:"not_before"`
	NotAfter  int64  `json:"not_after"`
}

func parseClientCertificate(certData, keyData string) (*clientCertificate, error) {
	if certData == "" || keyData == "" {
		return nil, errors.New("users[].user.client-certificate-data and users[].user.client-key-data must both be present")
	}
	if len(certData) > 256<<10 || len(keyData) > 64<<10 {
		return nil, errors.New("embedded client certificate or key exceeds the size limit")
	}
	certBytes, err := base64.StdEncoding.DecodeString(certData)
	if err != nil {
		return nil, errors.New("users[].user.client-certificate-data must be base64-encoded PEM")
	}
	certificates, err := publicCertificates(certBytes)
	if err != nil {
		return nil, errors.New("users[].user.client-certificate-data must contain a PEM certificate chain, leaf first")
	}
	key, err := base64.StdEncoding.DecodeString(keyData)
	defer clear(key)
	if err != nil {
		return nil, errors.New("users[].user.client-key-data must be base64-encoded PEM")
	}
	raw := bytes.TrimSpace(key)
	block, rest := pem.Decode(raw)
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || bytes.Count(raw, []byte("-----BEGIN ")) != 1 || !bytes.HasPrefix(raw, []byte("-----BEGIN "+block.Type+"-----")) {
		return nil, errors.New("users[].user.client-key-data must contain one unencrypted PEM private key")
	}
	defer clear(block.Bytes)
	switch block.Type {
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
	default:
		return nil, errors.New("unsupported client private key PEM type")
	}
	pair, err := tls.X509KeyPair(certificates, raw)
	if err != nil {
		return nil, errors.New("embedded client certificate and private key must be a matching TLS key pair")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, errors.New("invalid embedded client certificate")
	}
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageCertSign != 0 {
		return nil, errors.New("client-certificate-data must start with an end-user certificate; a CA signing key cannot be used")
	}
	if len(leaf.ExtKeyUsage)+len(leaf.UnknownExtKeyUsage) > 0 && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return nil, errors.New("client certificate does not permit TLS client authentication")
	}
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, errors.New("client certificate does not permit TLS signatures")
	}
	normalized := pem.EncodeToMemory(block)
	defer clear(normalized)
	return &clientCertificate{CertPEM: string(certificates), KeyPEM: string(normalized), NotBefore: leaf.NotBefore.Unix(), NotAfter: leaf.NotAfter.Unix()}, nil
}

func (r record) execStatus(sessionEnd, now time.Time) (map[string]string, error) {
	if !now.Before(sessionEnd) {
		return nil, errors.New("credential session expired")
	}
	deadline := credentialDeadline(r.Token, sessionEnd, now)
	out := map[string]string{}
	switch {
	case r.Certificate != nil && r.Token == "":
		cert := r.Certificate
		if now.Before(time.Unix(cert.NotBefore, 0)) {
			return nil, errors.New("Kubernetes client certificate is not yet valid")
		}
		end := time.Unix(cert.NotAfter, 0)
		if !now.Before(end) {
			return nil, errors.New("Kubernetes client certificate has expired; use kubeconfig-vault edit to replace it")
		}
		if end.Before(deadline) {
			deadline = end
		}
		out["clientCertificateData"] = cert.CertPEM
		out["clientKeyData"] = cert.KeyPEM
	case r.Certificate == nil && r.Token != "":
		if !now.Before(deadline) {
			return nil, errors.New("Kubernetes token has expired; use kubeconfig-vault edit to replace it")
		}
		out["token"] = r.Token
	default:
		return nil, errors.New("invalid credential record")
	}
	out["expirationTimestamp"] = deadline.UTC().Format(time.RFC3339Nano)
	return out, nil
}
