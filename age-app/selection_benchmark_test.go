package main

import (
	"encoding/json"
	"strconv"
	"testing"
)

// Measure selection reconciliation only; the edit and browser ceremony are
// outside the measured loop. Each iteration starts with the same source config.
func BenchmarkPreserveSelections(b *testing.B) {
	for _, count := range []int{10, 100, 1000} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			c := config{APIVersion: "v1", Kind: "Config", Current: "context-0",
				Clusters: []namedCluster{{Name: "cluster", Cluster: cluster{Server: "https://example.invalid"}}},
				Users:    []namedUser{{Name: "user", User: auth{Token: "synthetic"}}},
			}
			for i := range count {
				c.Contexts = append(c.Contexts, namedContext{Name: "context-" + strconv.Itoa(i), Context: contextConfig{Cluster: "cluster", User: "user"}})
			}
			source, err := json.Marshal(c)
			if err != nil {
				b.Fatal(err)
			}
			old := payload{Source: string(source), Portable: c, Projection: c}
			next := old
			next.Projection.Contexts = make([]namedContext, count)
			observed := c
			observed.Contexts = append([]namedContext(nil), c.Contexts...)
			for i := range observed.Contexts {
				observed.Contexts[i].Context.Namespace = "selected"
			}
			b.ReportAllocs()
			for b.Loop() {
				copy(next.Projection.Contexts, c.Contexts)
				preserveSelections(&old, &next, observed)
			}
			if next.Projection.Contexts[count-1].Context.Namespace != "selected" {
				b.Fatal("lost selected namespace")
			}
		})
	}
}
