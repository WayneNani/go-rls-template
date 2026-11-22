package store

import (
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestCheckTLS(t *testing.T) {
	for mode, wantOK := range map[string]bool{
		"disable":     false,
		"allow":       false,
		"prefer":      false,
		"require":     false, // encrypts but trusts any certificate
		"verify-ca":   false, // does not check the host name
		"verify-full": true,
	} {
		cfg, err := pgconn.ParseConfig("postgres://u:p@db.example.com/app?sslmode=" + mode)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkTLS(*cfg); (err == nil) != wantOK {
			t.Errorf("sslmode=%s: checkTLS() = %v, want ok=%v", mode, err, wantOK)
		}
	}
}
