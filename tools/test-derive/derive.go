// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0
//
// TEST-ONLY UTILITY — DO NOT SHIP TO PRODUCTION DEPLOYMENTS.
//
// derive.go produces a deterministic set of deaddrop secrets from a single
// memorable passphrase + hardcoded salt, intended only for the personal
// two-laptop test loop. It uses Argon2id at the same parameters as the
// production capsule, but the salt is fixed at compile time so output is
// reproducible across machines that share the binary version + phrase.
//
// Why this is unsafe for production:
//   1. Hardcoded salt + memorable phrase = offline brute-forceable if the
//      attacker has the binary AND a sample of derived output.
//   2. Deterministic derivation breaks any forward-secrecy story.
//   3. One phrase compromise = total compromise of derived secrets.
//
// Production path: keyring passcache + local profile file. These
// replacements are tracked as future work.

package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
)

var hardcodedSalt = [16]byte{
	0xa3, 0x1b, 0x7c, 0x4e, 0x9f, 0x02, 0xd8, 0x65,
	0x3a, 0xf1, 0x84, 0xb7, 0x0c, 0xe6, 0x59, 0x2d,
}

const (
	argonTime    = 3
	argonMemory  = 1 << 17 // 128 MiB
	argonThreads = 4
	argonKeyLen  = 128

	defaultLabel   = "deaddrop-test-derive-v1"
	prefixLabel    = "deaddrop-test-derive-v1-caddy-prefix"
	caddyPrefixLen = 16
	separator      = 0x1F
)

func derive(phrase, label string) []byte {
	input := append([]byte(phrase), separator)
	input = append(input, []byte(label)...)
	return argon2.IDKey(input, hardcodedSalt[:], argonTime, argonMemory, argonThreads, argonKeyLen)
}

func derivePrefix(phrase string) []byte {
	input := append([]byte(phrase), separator)
	input = append(input, []byte(prefixLabel)...)
	return argon2.IDKey(input, hardcodedSalt[:], argonTime, argonMemory, argonThreads, caddyPrefixLen)
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("test-derive", flag.ContinueOnError)
	fs.SetOutput(stderr)

	phraseFD := fs.Int("phrase-fd", -1, "Read passphrase from file descriptor N")
	phraseEnv := fs.String("phrase-env", "", "Read passphrase from environment variable VAR")
	phraseStdin := fs.Bool("phrase-stdin", false, "Read passphrase from stdin")
	relayURL := fs.String("relay-url", "", "Relay URL (passed through verbatim; mutually exclusive with --site-addr)")
	siteAddr := fs.String("site-addr", "", "Site address (e.g. deaddrop.example.com); CADDY_PREFIX is derived and the relay URL is constructed as https://<site>/<prefix>")
	label := fs.String("label", defaultLabel, "Derivation label")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	fmt.Fprintln(stderr, "test-derive: TEST-ONLY")

	if (*relayURL == "" && *siteAddr == "") || (*relayURL != "" && *siteAddr != "") {
		fmt.Fprintln(stderr, "error: exactly one of --relay-url or --site-addr is required")
		return 2
	}

	sourceCount := 0
	if *phraseFD >= 0 {
		sourceCount++
	}
	if *phraseEnv != "" {
		sourceCount++
	}
	if *phraseStdin {
		sourceCount++
	}
	if sourceCount != 1 {
		fmt.Fprintln(stderr, "error: exactly one of --phrase-fd, --phrase-env, or --phrase-stdin required")
		return 2
	}

	var phrase string
	switch {
	case *phraseFD >= 0:
		f := os.NewFile(uintptr(*phraseFD), "phrase-fd")
		if f == nil {
			fmt.Fprintf(stderr, "error: invalid file descriptor %d\n", *phraseFD)
			return 2
		}
		data, err := io.ReadAll(f)
		if err != nil {
			fmt.Fprintf(stderr, "error: reading phrase-fd %d: %v\n", *phraseFD, err)
			return 1
		}
		phrase = strings.TrimRight(string(data), "\n\r")
	case *phraseEnv != "":
		phrase = os.Getenv(*phraseEnv)
		if phrase == "" {
			fmt.Fprintf(stderr, "error: environment variable %s is empty or unset\n", *phraseEnv)
			return 2
		}
	case *phraseStdin:
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(stderr, "error: reading stdin: %v\n", err)
			return 1
		}
		phrase = strings.TrimRight(string(data), "\n\r")
	}

	if phrase == "" {
		fmt.Fprintln(stderr, "error: passphrase is empty")
		return 2
	}

	derived := derive(phrase, *label)
	defer func() {
		for i := range derived {
			derived[i] = 0
		}
	}()

	deploySecret := hex.EncodeToString(derived[0:32])
	writeToken := hex.EncodeToString(derived[32:64])
	bootstrapPA := base64.StdEncoding.EncodeToString(derived[64:96])
	capsulePB := base64.StdEncoding.EncodeToString(derived[96:128])

	finalRelayURL := *relayURL
	var caddyPrefix string
	if *siteAddr != "" {
		prefixBytes := derivePrefix(phrase)
		defer func() {
			for i := range prefixBytes {
				prefixBytes[i] = 0
			}
		}()
		caddyPrefix = hex.EncodeToString(prefixBytes)
		finalRelayURL = fmt.Sprintf("https://%s/%s", *siteAddr, caddyPrefix)
	}

	fmt.Fprintf(stdout, "export DEADDROP_RELAY=%q\n", finalRelayURL)
	fmt.Fprintf(stdout, "export DEADDROP_DEPLOY_SECRET=\"hex:%s\"\n", deploySecret)
	fmt.Fprintf(stdout, "export DEADDROP_WRITE_TOKEN=\"hex:%s\"\n", writeToken)
	fmt.Fprintf(stdout, "export DEADDROP_BOOTSTRAP_PA=%q\n", bootstrapPA)
	fmt.Fprintf(stdout, "export DEADDROP_CAPSULE_PASSPHRASE=%q\n", capsulePB)
	if caddyPrefix != "" {
		fmt.Fprintf(stdout, "export DEADDROP_CADDY_PREFIX=%q\n", caddyPrefix)
	}

	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
