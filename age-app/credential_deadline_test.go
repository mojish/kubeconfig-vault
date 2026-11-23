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
