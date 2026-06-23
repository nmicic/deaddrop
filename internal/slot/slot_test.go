// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package slot_test

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/nmicic/deaddrop/internal/slot"
)

//go:embed testdata/derive/slot_key.json
var slotKeyJSON []byte

//go:embed testdata/derive/service_id.json
var serviceIDJSON []byte

//go:embed testdata/derive/slot.json
var slotJSON []byte

// ---------------- fixture schemas ----------------

type slotKeyInputs struct {
	PSK    string `json:"PSK"`
	PairID string `json:"pair_id"`
}

type slotKeyCase struct {
	Name         string        `json:"name"`
	Inputs       slotKeyInputs `json:"inputs"`
	HMACInputHex string        `json:"hmac_input_hex"`
	ExpectedHex  string        `json:"expected_hex"`
}

type slotKeyFile struct {
	Cases []slotKeyCase `json:"cases"`
}

type serviceIDInputs struct {
	DeploySecret string `json:"DEPLOY_SECRET"`
	H            uint64 `json:"h"`
}

type serviceIDCase struct {
	Name         string          `json:"name"`
	Inputs       serviceIDInputs `json:"inputs"`
	HMACInputHex string          `json:"hmac_input_hex"`
	ExpectedHex  string          `json:"expected_hex"`
}

type serviceIDFile struct {
	Cases []serviceIDCase `json:"cases"`
}

type slotIDInputs struct {
	SlotKey string `json:"slot_key"`
	B       uint64 `json:"b"`
	Attempt uint32 `json:"attempt"`
}

type slotIDCase struct {
	Name         string       `json:"name"`
	Inputs       slotIDInputs `json:"inputs"`
	HMACInputHex string       `json:"hmac_input_hex"`
	ExpectedHex  string       `json:"expected_hex"`
}

type slotIDFile struct {
	Cases []slotIDCase `json:"cases"`
}

// ---------------- fixture loaders ----------------

func loadSlotKey(t *testing.T) slotKeyFile {
	t.Helper()
	var f slotKeyFile
	if err := json.Unmarshal(slotKeyJSON, &f); err != nil {
		t.Fatalf("slot_key.json: %v", err)
	}
	return f
}

func loadServiceID(t *testing.T) serviceIDFile {
	t.Helper()
	var f serviceIDFile
	if err := json.Unmarshal(serviceIDJSON, &f); err != nil {
		t.Fatalf("service_id.json: %v", err)
	}
	return f
}

func loadSlotID(t *testing.T) slotIDFile {
	t.Helper()
	var f slotIDFile
	if err := json.Unmarshal(slotJSON, &f); err != nil {
		t.Fatalf("slot.json: %v", err)
	}
	return f
}

func pickSvc(t *testing.T, f serviceIDFile, prefix string) serviceIDCase {
	t.Helper()
	for _, c := range f.Cases {
		if strings.HasPrefix(c.Name, prefix) {
			return c
		}
	}
	t.Fatalf("service_id case with prefix %q not found", prefix)
	return serviceIDCase{}
}

func pickSlot(t *testing.T, f slotIDFile, substr string) slotIDCase {
	t.Helper()
	for _, c := range f.Cases {
		if strings.Contains(c.Name, substr) {
			return c
		}
	}
	t.Fatalf("slot case containing %q not found", substr)
	return slotIDCase{}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex-decode %q: %v", s, err)
	}
	return b
}

// ---------------- tests ----------------

// 1. TestSlotKey_Canonical.
func TestSlotKey_Canonical(t *testing.T) {
	f := loadSlotKey(t)
	if len(f.Cases) == 0 {
		t.Fatalf("no slot_key cases")
	}
	c := f.Cases[0]
	psk := mustHex(t, c.Inputs.PSK)
	pairID := mustHex(t, c.Inputs.PairID)
	want := mustHex(t, c.ExpectedHex)

	got, err := slot.SlotKey(psk, pairID)
	if err != nil {
		t.Fatalf("SlotKey: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("slot_key mismatch\n  got:  %s\n  want: %s",
			hex.EncodeToString(got), c.ExpectedHex)
	}
}

// 2. TestSlotKey_HMACInput verifies the declared hmac_input_hex equals
// "slot-key-v1" || pair_id decoded from the canonical fixture.
func TestSlotKey_HMACInput(t *testing.T) {
	f := loadSlotKey(t)
	c := f.Cases[0]
	pairID := mustHex(t, c.Inputs.PairID)

	want := make([]byte, 0, 11+len(pairID))
	want = append(want, []byte("slot-key-v1")...)
	want = append(want, pairID...)

	if hex.EncodeToString(want) != c.HMACInputHex {
		t.Fatalf("slot_key HMAC input mismatch\n  got:  %s\n  want: %s",
			hex.EncodeToString(want), c.HMACInputHex)
	}
}

// 3. TestServiceID_Canonical.
func TestServiceID_Canonical(t *testing.T) {
	f := loadServiceID(t)
	c := pickSvc(t, f, "canonical")
	deploy := mustHex(t, c.Inputs.DeploySecret)
	want := mustHex(t, c.ExpectedHex)

	got, err := slot.ServiceID(deploy, c.Inputs.H)
	if err != nil {
		t.Fatalf("ServiceID: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("service_id mismatch\n  got:  %s\n  want: %s",
			hex.EncodeToString(got), c.ExpectedHex)
	}
}

// 4. TestServiceID_HMinus1.
func TestServiceID_HMinus1(t *testing.T) {
	f := loadServiceID(t)
	canonical := pickSvc(t, f, "canonical")
	c := pickSvc(t, f, "h-minus-1")

	deploy := mustHex(t, c.Inputs.DeploySecret)
	want := mustHex(t, c.ExpectedHex)
	canonicalOut := mustHex(t, canonical.ExpectedHex)

	got, err := slot.ServiceID(deploy, c.Inputs.H)
	if err != nil {
		t.Fatalf("ServiceID: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("h-minus-1 service_id mismatch")
	}
	if bytes.Equal(got, canonicalOut) {
		t.Fatalf("h-minus-1 output must differ from canonical")
	}
}

// 5. TestServiceID_HPlus1.
func TestServiceID_HPlus1(t *testing.T) {
	f := loadServiceID(t)
	canonical := pickSvc(t, f, "canonical")
	c := pickSvc(t, f, "h-plus-1")

	deploy := mustHex(t, c.Inputs.DeploySecret)
	want := mustHex(t, c.ExpectedHex)
	canonicalOut := mustHex(t, canonical.ExpectedHex)

	got, err := slot.ServiceID(deploy, c.Inputs.H)
	if err != nil {
		t.Fatalf("ServiceID: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("h-plus-1 service_id mismatch")
	}
	if bytes.Equal(got, canonicalOut) {
		t.Fatalf("h-plus-1 output must differ from canonical")
	}
}

// 6. TestServiceID_HMACInput — "svc" || enc_u64_be(h) for canonical.
func TestServiceID_HMACInput(t *testing.T) {
	f := loadServiceID(t)
	c := pickSvc(t, f, "canonical")

	var hBuf [8]byte
	binary.BigEndian.PutUint64(hBuf[:], c.Inputs.H)

	want := make([]byte, 0, 3+8)
	want = append(want, []byte("svc")...)
	want = append(want, hBuf[:]...)

	if hex.EncodeToString(want) != c.HMACInputHex {
		t.Fatalf("service_id HMAC input mismatch\n  got:  %s\n  want: %s",
			hex.EncodeToString(want), c.HMACInputHex)
	}
}

// 7. TestSlotID_Canonical.
func TestSlotID_Canonical(t *testing.T) {
	f := loadSlotID(t)
	c := pickSlot(t, f, "canonical current-minute")
	slotKey := mustHex(t, c.Inputs.SlotKey)
	want := mustHex(t, c.ExpectedHex)

	got, err := slot.SlotID(slotKey, c.Inputs.B, c.Inputs.Attempt)
	if err != nil {
		t.Fatalf("SlotID: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("slot_id mismatch\n  got:  %s\n  want: %s",
			hex.EncodeToString(got), c.ExpectedHex)
	}
}

// 8. TestSlotID_BPrev.
func TestSlotID_BPrev(t *testing.T) {
	f := loadSlotID(t)
	canonical := pickSlot(t, f, "canonical current-minute")
	c := pickSlot(t, f, "previous minute")

	slotKey := mustHex(t, c.Inputs.SlotKey)
	want := mustHex(t, c.ExpectedHex)
	canonicalOut := mustHex(t, canonical.ExpectedHex)

	got, err := slot.SlotID(slotKey, c.Inputs.B, c.Inputs.Attempt)
	if err != nil {
		t.Fatalf("SlotID: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("b-prev slot_id mismatch")
	}
	if bytes.Equal(got, canonicalOut) {
		t.Fatalf("b-prev output must differ from canonical")
	}
}

// 9. TestSlotID_BNext.
func TestSlotID_BNext(t *testing.T) {
	f := loadSlotID(t)
	canonical := pickSlot(t, f, "canonical current-minute")
	c := pickSlot(t, f, "next minute")

	slotKey := mustHex(t, c.Inputs.SlotKey)
	want := mustHex(t, c.ExpectedHex)
	canonicalOut := mustHex(t, canonical.ExpectedHex)

	got, err := slot.SlotID(slotKey, c.Inputs.B, c.Inputs.Attempt)
	if err != nil {
		t.Fatalf("SlotID: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("b-next slot_id mismatch")
	}
	if bytes.Equal(got, canonicalOut) {
		t.Fatalf("b-next output must differ from canonical")
	}
}

// 10. TestSlotID_Attempt1.
func TestSlotID_Attempt1(t *testing.T) {
	f := loadSlotID(t)
	canonical := pickSlot(t, f, "canonical current-minute")
	c := pickSlot(t, f, "attempt=1")

	slotKey := mustHex(t, c.Inputs.SlotKey)
	want := mustHex(t, c.ExpectedHex)
	canonicalOut := mustHex(t, canonical.ExpectedHex)

	got, err := slot.SlotID(slotKey, c.Inputs.B, c.Inputs.Attempt)
	if err != nil {
		t.Fatalf("SlotID: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("attempt=1 slot_id mismatch")
	}
	if bytes.Equal(got, canonicalOut) {
		t.Fatalf("attempt=1 output must differ from canonical attempt=0")
	}
}

// 11. TestSlotID_HMACInput — "slot" || enc_u64_be(b) || enc_u32_be(attempt).
func TestSlotID_HMACInput(t *testing.T) {
	f := loadSlotID(t)
	c := pickSlot(t, f, "canonical current-minute")

	var bBuf [8]byte
	binary.BigEndian.PutUint64(bBuf[:], c.Inputs.B)
	var aBuf [4]byte
	binary.BigEndian.PutUint32(aBuf[:], c.Inputs.Attempt)

	want := make([]byte, 0, 4+8+4)
	want = append(want, []byte("slot")...)
	want = append(want, bBuf[:]...)
	want = append(want, aBuf[:]...)

	if hex.EncodeToString(want) != c.HMACInputHex {
		t.Fatalf("slot_id HMAC input mismatch\n  got:  %s\n  want: %s",
			hex.EncodeToString(want), c.HMACInputHex)
	}
}

// 12. TestAEADKey_Canonical exercises the full derivation chain:
// SlotKey → ServiceID → SlotID → AEADKey, and asserts the canonical
// golden value already verified by the derivation fixtures.
func TestAEADKey_Canonical(t *testing.T) {
	psk := bytes.Repeat([]byte{0x02}, slot.PSKSize)
	pairID := bytes.Repeat([]byte{0x03}, slot.PairIDSize)
	deploy := bytes.Repeat([]byte{0x01}, slot.MinDeploySecretLen)
	const h uint64 = 500000
	const b uint64 = 30000000
	const attempt uint32 = 0
	const version byte = 0x01

	// from internal/crypto/testdata/aead/ad_binding.json canonical case
	const wantHex = "9d64cde9176f319b9bd1e2aabde028bdb1410a5e91c3a07dd8bf7c249864e9f3"

	slotKey, err := slot.SlotKey(psk, pairID)
	if err != nil {
		t.Fatalf("SlotKey: %v", err)
	}
	serviceID, err := slot.ServiceID(deploy, h)
	if err != nil {
		t.Fatalf("ServiceID: %v", err)
	}
	slotID, err := slot.SlotID(slotKey, b, attempt)
	if err != nil {
		t.Fatalf("SlotID: %v", err)
	}
	got, err := slot.AEADKey(psk, pairID, serviceID, slotID, version)
	if err != nil {
		t.Fatalf("AEADKey: %v", err)
	}
	want := mustHex(t, wantHex)
	if !bytes.Equal(got, want) {
		t.Fatalf("aead_key mismatch\n  got:  %s\n  want: %s",
			hex.EncodeToString(got), wantHex)
	}
}

// 13. TestSlotKey_BadPSKSize.
func TestSlotKey_BadPSKSize(t *testing.T) {
	pairID := make([]byte, slot.PairIDSize)
	_, err := slot.SlotKey(make([]byte, 31), pairID)
	if !errors.Is(err, slot.ErrBadPSKSize) {
		t.Fatalf("want ErrBadPSKSize, got %v", err)
	}
}

// 14. TestSlotKey_BadPairIDSize.
func TestSlotKey_BadPairIDSize(t *testing.T) {
	psk := make([]byte, slot.PSKSize)
	_, err := slot.SlotKey(psk, make([]byte, 7))
	if !errors.Is(err, slot.ErrBadPairIDSize) {
		t.Fatalf("want ErrBadPairIDSize, got %v", err)
	}
}

// 15. TestServiceID_BadDeploySecretLen — 31 bytes rejects; 48 bytes
// accepted (PROTOCOL.md §8: "32+ raw bytes").
func TestServiceID_BadDeploySecretLen(t *testing.T) {
	if _, err := slot.ServiceID(make([]byte, 31), 0); !errors.Is(err, slot.ErrBadDeploySecretLen) {
		t.Fatalf("31-byte: want ErrBadDeploySecretLen, got %v", err)
	}
	got, err := slot.ServiceID(make([]byte, 48), 0)
	if err != nil {
		t.Fatalf("48-byte: want nil, got %v", err)
	}
	if len(got) != slot.ServiceIDSize {
		t.Fatalf("48-byte: len = %d, want %d", len(got), slot.ServiceIDSize)
	}
}

// 16. TestSlotID_BadSlotKeySize.
func TestSlotID_BadSlotKeySize(t *testing.T) {
	_, err := slot.SlotID(make([]byte, 31), 0, 0)
	if !errors.Is(err, slot.ErrBadSlotKeySize) {
		t.Fatalf("want ErrBadSlotKeySize, got %v", err)
	}
}

// 17. TestAEADKey_BadPSKSize.
func TestAEADKey_BadPSKSize(t *testing.T) {
	_, err := slot.AEADKey(
		make([]byte, 31),
		make([]byte, slot.PairIDSize),
		make([]byte, slot.ServiceIDSize),
		make([]byte, slot.SlotIDSize),
		0x01,
	)
	if !errors.Is(err, slot.ErrBadPSKSize) {
		t.Fatalf("want ErrBadPSKSize, got %v", err)
	}
}

// 18. TestAEADKey_BadPairIDSize.
func TestAEADKey_BadPairIDSize(t *testing.T) {
	_, err := slot.AEADKey(
		make([]byte, slot.PSKSize),
		make([]byte, 7),
		make([]byte, slot.ServiceIDSize),
		make([]byte, slot.SlotIDSize),
		0x01,
	)
	if !errors.Is(err, slot.ErrBadPairIDSize) {
		t.Fatalf("want ErrBadPairIDSize, got %v", err)
	}
}

// 19. TestAEADKey_BadServiceIDSize.
func TestAEADKey_BadServiceIDSize(t *testing.T) {
	_, err := slot.AEADKey(
		make([]byte, slot.PSKSize),
		make([]byte, slot.PairIDSize),
		make([]byte, 15),
		make([]byte, slot.SlotIDSize),
		0x01,
	)
	if !errors.Is(err, slot.ErrBadServiceIDSize) {
		t.Fatalf("want ErrBadServiceIDSize, got %v", err)
	}
}

// 20. TestAEADKey_BadSlotIDSize.
func TestAEADKey_BadSlotIDSize(t *testing.T) {
	_, err := slot.AEADKey(
		make([]byte, slot.PSKSize),
		make([]byte, slot.PairIDSize),
		make([]byte, slot.ServiceIDSize),
		make([]byte, 15),
		0x01,
	)
	if !errors.Is(err, slot.ErrBadSlotIDSize) {
		t.Fatalf("want ErrBadSlotIDSize, got %v", err)
	}
}

// 21. TestSlotKey_Deterministic.
func TestSlotKey_Deterministic(t *testing.T) {
	psk := bytes.Repeat([]byte{0x7f}, slot.PSKSize)
	pairID := bytes.Repeat([]byte{0x11}, slot.PairIDSize)
	a, err := slot.SlotKey(psk, pairID)
	if err != nil {
		t.Fatalf("SlotKey a: %v", err)
	}
	b, err := slot.SlotKey(psk, pairID)
	if err != nil {
		t.Fatalf("SlotKey b: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("SlotKey not deterministic")
	}
}

// 22. TestSlotID_Deterministic.
func TestSlotID_Deterministic(t *testing.T) {
	slotKey := bytes.Repeat([]byte{0x55}, slot.SlotKeySize)
	a, err := slot.SlotID(slotKey, 42, 0)
	if err != nil {
		t.Fatalf("SlotID a: %v", err)
	}
	b, err := slot.SlotID(slotKey, 42, 0)
	if err != nil {
		t.Fatalf("SlotID b: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("SlotID not deterministic")
	}
}
