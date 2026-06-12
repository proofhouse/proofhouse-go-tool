// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Proofhouse

// Command proofhouse-go-tool provides the reference binary for the Proofhouse
// Go reference repository. The binary itself stays intentionally minimal;
// its purpose: give the surrounding gates something to compile against
// and ship through the release pipeline. The repository's value sits in
// the supply chain plumbing around the binary, not in the binary's own
// command surface.
package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/proofhouse/proofhouse-go-tool/internal/buildmeta"
)

func main() {
	rootCmd := newRootCmd()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "proofhouse-go-tool",
		Short:         "Reference binary for the Proofhouse Go reference repository",
		Version:       buildmeta.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(newVersionCmd())
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, commit, and build date",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			info := buildmeta.Get()
			cmd.Printf("proofhouse-go-tool %s\ncommit: %s\ndate:   %s\n", info.Version, info.Commit, info.Date)
		},
	}
}
