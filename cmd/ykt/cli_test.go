package main

import (
	"testing"

	"github.com/spf13/cobra"
)

// TestStoreOptional: help/completion (and the leaf subcommands under completion)
// and annotated commands run without a store; everything else needs one — so
// `ykt completion bash` and `ykt docs` work on a store-less machine.
func TestStoreOptional(t *testing.T) {
	root := &cobra.Command{Use: "ykt"}
	completion := &cobra.Command{Use: "completion"}
	bash := &cobra.Command{Use: "bash"}
	completion.AddCommand(bash)
	docs := &cobra.Command{Use: "docs", Annotations: storeOptionalAnn}
	status := &cobra.Command{Use: "status"}
	root.AddCommand(completion, docs, status)

	for _, tc := range []struct {
		cmd  *cobra.Command
		want bool
	}{
		{bash, true},       // leaf under `completion`
		{completion, true}, // the completion command itself
		{docs, true},       // annotated store-optional
		{status, false},    // needs a store
	} {
		if got := storeOptional(tc.cmd); got != tc.want {
			t.Errorf("storeOptional(%q) = %v, want %v", tc.cmd.Name(), got, tc.want)
		}
	}
}

// TestDocRank: README leads, listed docs keep their order, unlisted sort last.
func TestDocRank(t *testing.T) {
	if docRank("README.md") >= docRank("INSTALL.md") {
		t.Error("README.md must rank before INSTALL.md")
	}
	if docRank("INSTALL.md") >= docRank("SECURITY.md") {
		t.Error("INSTALL.md must rank before SECURITY.md")
	}
	if docRank("SOMETHING.md") != 100 {
		t.Errorf("unlisted doc rank = %d, want 100", docRank("SOMETHING.md"))
	}
}
