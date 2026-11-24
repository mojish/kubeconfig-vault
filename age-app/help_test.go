package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRecoveryHelpStartsWithSelectedCommand(t *testing.T) {
	for _, topic := range []string{"backup", "recover", "restore", "export"} {
		t.Run(topic, func(t *testing.T) {
			var out bytes.Buffer
			if err := printHelp(&out, []string{topic}); err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(out.String(), "kubeconfig-vault "+topic+" ") {
				t.Errorf("%s help did not lead with its invocation", topic)
			}
		})
	}
	var overview bytes.Buffer
	if err := printHelp(&overview, []string{"recovery"}); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"backup", "recover", "restore", "export"} {
		if !strings.Contains(overview.String(), "\n  "+command+" ") {
			t.Errorf("recovery overview omitted %s", command)
		}
	}
}
