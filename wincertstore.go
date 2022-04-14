package wincertstore

import (
	"encoding/pem"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Store is a certificate store.
type Store struct {
	h windows.Handle
}

const (
	// CA is the name of the system store that contains
	// intermediate certificates.
	CA = "CA"
	// My is the name of the system store that contains per-user
	// private keys.
	//
	// For TLS servers and client certs.
	My = "MY"
	// Root is the name of the system store that contains root
	// certificates.
	Root = "ROOT"
)

// OpenSystemStore opens the named system certificate store.
func OpenSystemStore(name string) (*Store, error) {
	system, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	h, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		windows.PKCS_7_ASN_ENCODING|windows.X509_ASN_ENCODING,
		0,
		windows.CERT_SYSTEM_STORE_LOCAL_MACHINE,
		uintptr(unsafe.Pointer(system)),
	)
	if err != nil {
		return nil, err
	}
	return &Store{h: h}, nil
}

// OpenStore creates an in-memory certificate store.
func OpenStore() (*Store, error) {
	h, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_MEMORY,
		windows.PKCS_7_ASN_ENCODING|windows.X509_ASN_ENCODING,
		0,
		windows.CERT_STORE_CREATE_NEW_FLAG,
		0,
	)
	if err != nil {
		return nil, err
	}
	return &Store{h: h}, nil
}

func (s *Store) Close() error {
	return windows.CertCloseStore(s.h, 0)
}

// AppendCertsFromPEM appends the PEM-encoded certificates to the
// store and reports whether at least one certificate was added.
func (s *Store) AppendCertsFromPEM(data []byte) error {
	for len(data) > 0 {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" || len(b.Headers) != 0 {
			return fmt.Errorf("winhttp: block not a 'CERTIFICATE'")
		}
		if len(b.Bytes) == 0 {
			return errors.New("winhttp: empty block")
		}
		cert, err := windows.CertCreateCertificateContext(
			windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
			&b.Bytes[0],
			uint32(len(b.Bytes)),
		)
		if err != nil {
			return fmt.Errorf("winhttp: unable to create cert context: %w", err)
		}
		err = windows.CertAddCertificateContextToStore(
			s.h,
			cert,
			windows.CERT_STORE_ADD_NEW,
			nil,
		)
		windows.CertFreeCertificateContext(cert)
		if err != nil {
			return fmt.Errorf("winhttp: unable to add cert to store: %w", err)
		}
	}
	return nil
}

// RemoveCertsFromPEM removes the PEM-encoded certificates from
// the store.
func (s *Store) RemoveCertsFromPEM(data []byte) error {
	var errs []error
	for len(data) > 0 {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" || len(b.Headers) != 0 {
			continue
		}
		if len(b.Bytes) == 0 {
			continue
		}
		if err := s.removeCert(b.Bytes); err != nil {
			errs = append(errs, err)
		}
	}
	switch len(errs) {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("winhttp: %w", errs[0])
	default:
		return fmt.Errorf("winhttp: %w (and %d other errors)", errs[0], len(errs)-1)
	}
}

// removeCerts removes the certificate from the store.
func (s *Store) removeCert(buf []byte) error {
	targ, err := windows.CertCreateCertificateContext(
		windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
		&buf[0],
		uint32(len(buf)),
	)
	if err != nil {
		return fmt.Errorf("unable to parse certificate: %w", err)
	}
	const (
		CERT_ID_ISSUER_SERIAL_NUMBER = 1
	)
	// typedef struct _CERT_ID {
	//   DWORD dwIdChoice;
	//   union {
	//     CERT_ISSUER_SERIAL_NUMBER IssuerSerialNumber;
	//     CRYPT_HASH_BLOB           KeyId;
	//     CRYPT_HASH_BLOB           HashId;
	//   } DUMMYUNIONNAME;
	// } CERT_ID, *PCERT_ID;
	//
	// typedef struct _CERT_ISSUER_SERIAL_NUMBER {
	//   CERT_NAME_BLOB     Issuer;
	//   CRYPT_INTEGER_BLOB SerialNumber;
	// } CERT_ISSUER_SERIAL_NUMBER, *PCERT_ISSUER_SERIAL_NUMBER;
	certID := struct {
		idChoice uint32
		name     windows.CertNameBlob
		serial   windows.CryptIntegerBlob
	}{
		idChoice: CERT_ID_ISSUER_SERIAL_NUMBER,
		name:     targ.CertInfo.Issuer,
		serial:   targ.CertInfo.SerialNumber,
	}
	cert, err := windows.CertFindCertificateInStore(
		s.h,
		windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
		0,
		windows.CERT_FIND_CERT_ID,
		unsafe.Pointer(&certID),
		nil,
	)
	if err != nil {
		const (
			notFound = windows.Errno(windows.CRYPT_E_NOT_FOUND)
		)
		if errors.Is(err, notFound) {
			return nil
		}
		return fmt.Errorf("unable to enumerate certificates: %w", err)
	}
	err = windows.CertDeleteCertificateFromStore(cert)
	if err != nil {
		return fmt.Errorf("unable to delete certificate: %w", err)
	}
	return nil
}
