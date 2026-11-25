package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"

	"filippo.io/age"
)

type repairTarget struct {
	entry       string
	alias, link os.FileInfo
	snap        *snapshot
}

func (s *service) repairLocation(path string) (*repairTarget, error) {
	if err := checkPrivateDir(s.state); err != nil {
		return nil, err
	}
	paths, err := s.editPaths()
	if err != nil {
		return nil, err
	}
	if len(paths) > 0 {
		return nil, errors.New("preserve or finish the open plaintext edit before repair")
	}
	entry, err := clientEntry(s.state, path)
	if err != nil {
		return nil, err
	}
	alias, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	link, err := os.Lstat(entry)
	if err != nil || !s.isLinked(entry) {
		return nil, errors.New("repair requires a client already linked to this vault")
	}
	id, err := currentID(s.state)
	if err != nil || id == "" {
		return nil, errors.New("repair requires an active vault generation")
	}
	dir := filepath.Join(s.state, "generations", id)
	for _, parent := range []string{filepath.Dir(dir), dir} {
		if err := checkPrivateDir(parent); err != nil {
			return nil, err
		}
	}
	if present, err := existsEntry(filepath.Join(dir, "kubeconfig")); err != nil || present {
		return nil, errors.New("repair requires a missing generated kubeconfig; existing entry preserved")
	}
	return &repairTarget{entry: entry, alias: alias, link: link, snap: &snapshot{ID: id}}, nil
}

func (s *service) selectRepair(path string) (*repairTarget, error) {
	target, err := s.repairLocation(path)
	if err != nil {
		return nil, err
	}
	id := target.snap.ID
	dir := filepath.Join(s.state, "generations", id)
	snap, err := loadMetadata(dir, id)
	if err != nil {
		return nil, err
	}
	if _, err = age.ParseHybridRecipient(snap.Meta.Recovery); err != nil {
		return nil, errors.New("invalid recovery recipient")
	}
	snap.Cipher, err = readBounded(filepath.Join(dir, "vault.age"), maxVault, true)
	if err != nil {
		return nil, err
	}
	target.snap = snap
	return target, nil
}

// Reconstruct the executable and its arguments from the installed helper and
// compare them with the authenticated settings. Never resolve external CA paths.
func (s *service) repairedConfig(p *payload) ([]byte, error) {
	for _, c := range p.Portable.Clusters {
		if c.Cluster.CAFile != "" {
			return nil, errors.New("repair requires embedded public CA data")
		}
	}
	if err := validateProjectionProxies(p.Portable); err != nil {
		return nil, err
	}
	if len(p.Projection.Users) == 0 || p.Projection.Users[0].User.Exec == nil {
		return nil, errors.New("missing authenticated exec command")
	}
	command := p.Projection.Users[0].User.Exec.Command
	if command != s.executable && (command != filepath.Join(filepath.Dir(s.executable), legacyCommandName) || installedCommand(command) != s.executable) {
		return nil, errors.New("repair requires the original installation path or its installed compatibility link")
	}
	ids := map[string]bool{}
	for _, r := range p.Records {
		if !validID.MatchString(r.ID) || ids[r.ID] {
			return nil, errors.New("invalid or duplicate credential ID")
		}
		ids[r.ID] = true
	}
	rebuilt, err := prepareParsed(p.Portable, nil, "", s.state, command, p)
	if err != nil {
		return nil, err
	}
	if !equalProjection(rebuilt.Projection, p.Projection) || !reflect.DeepEqual(rebuilt.Records, p.Records) {
		return nil, errors.New("authenticated configuration and credential bindings disagree")
	}
	// Only the authenticated snapshot can restore these selections. Changes
	// made with kubectl since the last encrypted save existed in the lost file.
	out := p.Projection
	out.Preferences = nil
	return serializeConfig(out)
}

func (s *service) repair(ctx context.Context, path string) (any, error) {
	target, err := s.selectRepair(path)
	if err != nil {
		return nil, err
	}
	c, err := newCeremony(ctx, repairLinkApproval, s.browser, 1)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() { c.finish(ok) }()
	p, err := decryptPayload(target.snap.Cipher, browserKey{c, target.snap.Meta.Identity})
	if err != nil {
		return nil, c.failure(err)
	}
	if p.Meta != target.snap.Meta {
		return nil, errors.New("vault metadata differs from authenticated settings")
	}
	data, err := s.repairedConfig(p)
	if err != nil {
		return nil, err
	}
	if err = s.publishRepair(ctx, path, target, data); err != nil {
		return nil, err
	}
	ok = true
	return "Restored the linked kubeconfig from the last encrypted save.", nil
}

func (s *service) publishRepair(ctx context.Context, path string, target *repairTarget, data []byte) error {
	sameLink := func(a, b os.FileInfo) bool { return os.SameFile(a, b) && a.ModTime().Equal(b.ModTime()) }
	sameLocation := func(now *repairTarget) bool {
		return target.entry == now.entry && target.snap.ID == now.snap.ID && sameLink(target.alias, now.alias) && sameLink(target.link, now.link)
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		now, err := s.selectRepair(path)
		if err != nil {
			return err
		}
		if !sameLocation(now) || now.snap.Meta != target.snap.Meta || !bytes.Equal(now.snap.Cipher, target.snap.Cipher) {
			return errors.New("client link or vault changed during repair; retry")
		}
		return ctx.Err()
	}
	// Only the generation file is written. An exclusive publish protects it
	// without leaving kubectl lockfiles behind if the repair process exits.

	now, err := s.repairLocation(path)
	if err != nil {
		return err
	}
	if !sameLocation(now) {
		return errors.New("client link or generation changed before repair")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	dest := filepath.Join(s.state, "generations", target.snap.ID, "kubeconfig")
	return publishNewChecked(dest, data, check)
}
