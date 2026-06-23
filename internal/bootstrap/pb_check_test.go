// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"testing"
)

func TestCheckPBNotPA_SamePassphrase(t *testing.T) {
	pk := DerivePassphraseKey([]byte("test-pa"))
	defer zeroize(pk)

	reuse, err := CheckPBNotPA(pk, []byte("test-pa"))
	if err != nil {
		t.Fatal(err)
	}
	if !reuse {
		t.Fatal("expected reuse=true for same passphrase")
	}
}

func TestCheckPBNotPA_DifferentPassphrase(t *testing.T) {
	pk := DerivePassphraseKey([]byte("test-pa"))
	defer zeroize(pk)

	reuse, err := CheckPBNotPA(pk, []byte("different-pb"))
	if err != nil {
		t.Fatal(err)
	}
	if reuse {
		t.Fatal("expected reuse=false for different passphrase")
	}
}

func TestCheckPBNotPA_Zeroizes(t *testing.T) {
	pk := DerivePassphraseKey([]byte("test-pa"))
	defer zeroize(pk)

	r1, err1 := CheckPBNotPA(pk, []byte("test-pa"))
	if err1 != nil {
		t.Fatal(err1)
	}
	r2, err2 := CheckPBNotPA(pk, []byte("test-pa"))
	if err2 != nil {
		t.Fatal(err2)
	}
	if r1 != r2 {
		t.Fatal("non-deterministic results")
	}
}
