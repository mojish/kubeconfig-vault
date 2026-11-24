package main

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

func TestClientRefreshDeadline(t *testing.T) {
	now := time.Unix(1800000000, 0)
	jwt := func(exp time.Time) string {
		claims := fmt.Sprintf(`{"exp":%d}`, exp.Unix())
		return "test." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".test"
	}
	for _, tc := range []struct {
		name          string
		token         string
		session, want time.Duration
	}{
		{"opaque", "synthetic", time.Hour, time.Minute},
		{"long JWT", jwt(now.Add(2 * time.Hour)), time.Hour, time.Minute},
		{"short JWT", jwt(now.Add(10 * time.Second)), time.Hour, 10 * time.Second},
		{"short session", "synthetic", 5 * time.Second, 5 * time.Second},
		{"expired JWT", jwt(now.Add(-time.Second)), time.Hour, -time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := credentialDeadline(tc.token, now.Add(tc.session), now); !got.Equal(now.Add(tc.want)) {
				t.Errorf("refresh in %s, want %s", got.Sub(now), tc.want)
			}
		})
	}
}

func TestNumericDateCredentialDelivery(t *testing.T) {
	now := time.Unix(1800000000, 0)
	for _, tc := range []struct {
		name, exp string
		want      time.Duration
	}{
		{"fractional seconds", "1800000012.5", 12500 * time.Millisecond},
		{"decimal tenth of a second", "1800000000.1", 100 * time.Millisecond},
		{"less than a nanosecond before the next second", "1800000000.99999999999", time.Second - time.Nanosecond},
		{"exponent notation", "1.8000000125e9", 12500 * time.Millisecond},
		{"expired fraction", "1.7999999995e9", -500 * time.Millisecond},
		{"beyond the client cache", "9.3e18", time.Minute},
		{"very distant future", "1e9999999999999999", time.Minute},
		{"effectively epoch", "1e-9999999999999999", -now.Sub(time.Unix(0, 0))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := []byte(`{"exp":` + tc.exp + `}`)
			token := "test." + base64.RawURLEncoding.EncodeToString(claims) + ".test"
			if got := credentialDeadline(token, now.Add(time.Hour), now); !got.Equal(now.Add(tc.want)) {
				t.Fatalf("refresh in %s, want %s", got.Sub(now), tc.want)
			}
			rec := record{Token: token}
			status, err := rec.execStatus(now.Add(time.Hour), now)
			if tc.want <= 0 {
				if err == nil || status != nil {
					t.Fatal("an expired token was delivered")
				}
				return
			}
			wire, parseErr := time.Parse(time.RFC3339, status["expirationTimestamp"])
			if err != nil || status["token"] != token || parseErr != nil || !wire.Equal(now.Add(tc.want)) {
				t.Fatal("valid token did not receive the expected client refresh deadline")
			}
		})
	}
}

func TestExpiredSessionWithValidToken(t *testing.T) {
	now := time.Unix(1800000000, 0)
	status, err := (record{Token: "synthetic"}).execStatus(now, now)
	if err == nil || err.Error() != "credential session expired" || status != nil {
		t.Fatal("expected a session-expiry diagnostic for a still-valid credential")
	}
}
