// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import "syscall"

// prSetDumpable is the prctl option number for PR_SET_DUMPABLE. It's
// a stable Linux ABI constant; hardcoding avoids a cgo-style indirect
// dependency for a two-int syscall.
const prSetDumpable = 4

// Mlockall locks all current + future pages of the process in RAM so
// no secret material (slot ciphertext, keys, stack-resident
// plaintext) can be paged out to swap (D-39).
//
// Returns nil on success, the syscall error otherwise. Typical
// failures: EPERM (CAP_IPC_LOCK or RLIMIT_MEMLOCK not granted) or
// ENOMEM (RLIMIT_MEMLOCK too low). main.go decides whether the error
// is fatal; --local-only downgrades it to a warning.
func Mlockall() error {
	return syscall.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE)
}

// DisableCoreDump sets PR_SET_DUMPABLE=0 via prctl so the kernel will
// not generate a core file on process crash and will not expose
// /proc/[pid]/mem to ptrace attachers — both would leak PSKs, slot
// plaintext, and slot_key material (D-39).
//
// Returns nil on success, the errno otherwise.
func DisableCoreDump() error {
	_, _, errno := syscall.RawSyscall(
		syscall.SYS_PRCTL,
		prSetDumpable, // option
		0,             // arg2: not dumpable
		0,             // arg3: unused for PR_SET_DUMPABLE
	)
	if errno != 0 {
		return errno
	}
	return nil
}
