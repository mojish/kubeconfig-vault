package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

// Keep the active generation even after a clock adjustment or a manual restore.
func (s *service) prune(ctx context.Context, keep int) (any, error) {
	if keep < 1 {
		return nil, errors.New("keep at least one generation")
	}
	if len(s.editPaths()) != 0 {
		return nil, errors.New("finish or discard the open edit before pruning")
	}
	_, snapshot, err := s.open(ctx, "Verify your vault before pruning old generations")
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(s.state, "generations")
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	type generation struct {
		name string
		date time.Time
	}
	var old []generation
	for _, entry := range files {
		if !entry.IsDir() || !validID.MatchString(entry.Name()) || entry.Name() == snapshot.ID {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		old = append(old, generation{entry.Name(), info.ModTime()})
	}
	sort.SliceStable(old, func(i, j int) bool { return old[i].date.After(old[j].date) })
	removed := 0
	for i := keep - 1; i < len(old); i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		active, err := currentID(s.state)
		if err != nil || active != snapshot.ID {
			return nil, errors.New("active generation changed; pruning stopped")
		}
		retired := filepath.Join(dir, old[i].name)
		entries, err := os.ReadDir(retired)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !e.Type().IsRegular() || (e.Name() != "vault.age" && e.Name() != "metadata.json" && e.Name() != "kubeconfig") {
				return nil, errors.New("unexpected file in a retired generation; pruning stopped")
			}
		}
		for _, e := range entries {
			if err := os.Remove(filepath.Join(retired, e.Name())); err != nil {
				return nil, err
			}
		}
		if err := os.Remove(retired); err != nil {
			return nil, err
		}
		removed++
	}
	if err := syncDir(dir); err != nil {
		return nil, err
	}
	return fmt.Sprintf("Removed %d older encrypted generation(s).", removed), nil
}

func (s *service) history(args []string) error {
	if len(args) != 3 || args[0] != "prune" || args[1] != "--keep" {
		return errors.New("usage: history prune --keep COUNT")
	}
	n, err := strconv.Atoi(args[2])
	if err != nil || n < 1 {
		return errors.New("keep must be a positive number")
	}
	return s.clientAction(request{Op: "prune", Keep: n})
}
