// A private-stdio driver for synthetic browser/native interoperability tests.
// It accepts no paths and never reads application state or user credentials.
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"

	"filippo.io/age"
)

const sample = "SYNTHETIC-AGE-PRF-PAYLOAD-NOT-A-KUBERNETES-TOKEN"
const recipientType = "age-encryption.org/fido2prf"

type stanza struct {
	Type string   `json:"type"`
	Args []string `json:"args"`
	Body []byte   `json:"body"`
}

type message struct {
	Op         string   `json:"op,omitempty"`
	Event      string   `json:"event,omitempty"`
	Error      string   `json:"error,omitempty"`
	FileKey    []byte   `json:"fileKey,omitempty"`
	Ciphertext []byte   `json:"ciphertext,omitempty"`
	Stanzas    []stanza `json:"stanzas,omitempty"`
	Matched    bool     `json:"matched,omitempty"`
}

type protocol struct {
	in       *bufio.Scanner
	out      *json.Encoder
	firstKey []byte // Only synthetic: models a key captured from an earlier session.
}

func (p *protocol) send(m message) error { return p.out.Encode(m) }
func (p *protocol) receive() (message, error) {
	if !p.in.Scan() {
		return message{}, io.EOF
	}
	var m message
	if err := json.Unmarshal(p.in.Bytes(), &m); err != nil {
		return m, errors.New("invalid test message")
	}
	return m, nil
}

func (p *protocol) Wrap(key []byte) ([]*age.Stanza, error) {
	if p.firstKey == nil {
		p.firstKey = bytes.Clone(key)
	}
	if err := p.send(message{Event: "wrap", FileKey: key}); err != nil {
		return nil, err
	}
	m, err := p.receive()
	if err != nil || m.Error != "" {
		return nil, errors.New("browser wrapping failed")
	}
	if len(m.Stanzas) != 1 {
		return nil, errors.New("unexpected recipient count")
	}
	s := m.Stanzas[0]
	if s.Type != recipientType || len(s.Args) != 1 || len(s.Body) != 32 {
		return nil, errors.New("invalid browser stanza")
	}
	nonce, err := base64.RawStdEncoding.Strict().DecodeString(s.Args[0])
	if err != nil || len(nonce) != 16 {
		return nil, errors.New("invalid browser nonce")
	}
	return []*age.Stanza{{Type: s.Type, Args: s.Args, Body: s.Body}}, nil
}

// Match the upstream fido2prf recipient labels. Hybrid recovery avoids silently
// downgrading this recipient when mixing it with a classical public-key recipient.
func (p *protocol) WrapWithLabels(key []byte) ([]*age.Stanza, []string, error) {
	s, err := p.Wrap(key)
	return s, []string{"postquantum"}, err
}

func (p *protocol) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	var wire []stanza
	for _, s := range stanzas {
		if s.Type == recipientType {
			wire = append(wire, stanza{s.Type, s.Args, s.Body})
		}
	}
	if len(wire) == 0 {
		return nil, age.ErrIncorrectIdentity
	}
	if err := p.send(message{Event: "unwrap", Stanzas: wire}); err != nil {
		return nil, err
	}
	m, err := p.receive()
	if err != nil || m.Error != "" || len(m.FileKey) != 16 {
		return nil, errors.New("browser unwrapping failed")
	}
	return m.FileKey, nil
}

type capturedIdentity []byte

func (k capturedIdentity) Unwrap(_ []*age.Stanza) ([]byte, error) { return []byte(k), nil }

func matches(ciphertext []byte, identity age.Identity) bool {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return false
	}
	plain, err := io.ReadAll(io.LimitReader(r, 4096))
	defer clear(plain)
	return err == nil && string(plain) == sample
}

func run() error {
	p := &protocol{in: bufio.NewScanner(os.Stdin), out: json.NewEncoder(os.Stdout)}
	p.in.Buffer(make([]byte, 4096), 128*1024)
	recovery, err := age.GenerateHybridIdentity()
	if err != nil {
		return err
	}
	// Reparse the synthetic recovery identity to exercise the portable encoding.
	recovery, err = age.ParseHybridIdentity(recovery.String())
	if err != nil {
		return err
	}
	wrongRecovery, err := age.GenerateHybridIdentity()
	if err != nil {
		return err
	}
	if err := p.send(message{Event: "ready"}); err != nil {
		return err
	}
	for {
		m, err := p.receive()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		switch m.Op {
		case "seal":
			var output bytes.Buffer
			w, err := age.Encrypt(&output, p, recovery.Recipient())
			if err == nil {
				_, err = io.WriteString(w, sample)
			}
			if err == nil {
				err = w.Close()
			}
			if err != nil {
				_ = p.send(message{Event: "failed"})
				continue
			}
			err = p.send(message{Event: "sealed", Ciphertext: output.Bytes()})
			if err != nil {
				return err
			}
		case "open", "recover", "wrong-recovery", "captured-key":
			var identity age.Identity = p
			switch m.Op {
			case "recover":
				identity = recovery
			case "wrong-recovery":
				identity = wrongRecovery
			case "captured-key":
				identity = capturedIdentity(p.firstKey)
			}
			if err := p.send(message{Event: "opened", Matched: matches(m.Ciphertext, identity)}); err != nil {
				return err
			}
		case "stop":
			clear(p.firstKey)
			return nil
		default:
			return errors.New("unknown test operation")
		}
	}
}

func main() {
	if err := run(); err != nil {
		// Never echo payloads, callback values, or library errors containing input.
		_, _ = os.Stderr.WriteString("Synthetic age driver failed.\n")
		os.Exit(1)
	}
}
