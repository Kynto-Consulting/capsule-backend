package data

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

// CertProvider supplies server certificates for the connections the gateway terminates (capsule/1 tunnel and
// routes in `terminate` mode). G9 plugs the ACME/wildcard implementation in here; the gateway only needs this method.
type CertProvider interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// FileCerts serves certificates from PEM files and reloads them when they change on disk (renewal) or on Reload.
// Several pairs may be given; the first that supports the ClientHello is used.
type FileCerts struct {
	certFiles, keyFiles []string
	cur                 atomic.Pointer[[]tls.Certificate]
	mtimes              []time.Time
}

// NewFileCerts loads the pairs once; it fails if any cannot be read.
func NewFileCerts(certFiles, keyFiles []string) (*FileCerts, error) {
	if len(certFiles) == 0 || len(certFiles) != len(keyFiles) {
		return nil, errors.New("certificate and key file lists must be non-empty and of the same length")
	}
	f := &FileCerts{certFiles: certFiles, keyFiles: keyFiles}
	if err := f.Reload(); err != nil {
		return nil, err
	}
	return f, nil
}

// Reload re-reads every pair; on any error the previous certificates stay in force.
func (f *FileCerts) Reload() error {
	certs := make([]tls.Certificate, 0, len(f.certFiles))
	mt := make([]time.Time, len(f.certFiles))
	for i := range f.certFiles {
		c, err := tls.LoadX509KeyPair(f.certFiles[i], f.keyFiles[i])
		if err != nil {
			return fmt.Errorf("loading certificate pair %d: %w", i, err)
		}
		certs = append(certs, c)
		if st, err := os.Stat(f.certFiles[i]); err == nil {
			mt[i] = st.ModTime()
		}
	}
	f.cur.Store(&certs)
	f.mtimes = mt
	return nil
}

// Watch reloads when a certificate file's modification time changes, until ctx ends.
func (f *FileCerts) Watch(ctx context.Context, every time.Duration, onErr func(error)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			changed := false
			for i, p := range f.certFiles {
				if st, err := os.Stat(p); err == nil && !st.ModTime().Equal(f.mtimes[i]) {
					changed = true
				}
			}
			if changed {
				if err := f.Reload(); err != nil && onErr != nil {
					onErr(err)
				}
			}
		}
	}
}

// GetCertificate implements CertProvider.
func (f *FileCerts) GetCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cs := f.cur.Load()
	if cs == nil {
		return nil, errors.New("no certificate loaded")
	}
	for i := range *cs {
		if h.SupportsCertificate(&(*cs)[i]) == nil {
			return &(*cs)[i], nil
		}
	}
	return nil, errors.New("no certificate for this name")
}

// StaticCert serves one fixed certificate (tests and simple deployments).
type StaticCert struct{ Cert tls.Certificate }

// GetCertificate implements CertProvider.
func (s StaticCert) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := s.Cert
	return &c, nil
}
