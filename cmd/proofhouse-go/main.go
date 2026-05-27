// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Proofhouse

// Command proofhouse-go is the reference binary for the Proofhouse Go
// reference repository. The binary itself is intentionally minimal — its
// purpose is to give the repository something to build, sign, and release
// so the surrounding gates have a target to operate on. The value of this
// repository sits in the verification, supply-chain, and release plumbing
// around the binary, not in the binary's own command surface.
package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/proofhouse/proofhouse-go/internal/buildmeta"
)

func main() {
	rootCmd := newRootCmd()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "proofhouse-go",
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
			cmd.Printf("proofhouse-go %s\ncommit: %s\ndate:   %s\n", info.Version, info.Commit, info.Date)
		},
	}
}
