// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package passcache

func New() (Cache, error) {
	return nil, ErrUnsupported
}
