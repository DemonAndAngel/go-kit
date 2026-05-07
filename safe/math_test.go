package safe

import (
	"math"
	"testing"
)

func TestAddInt64(t *testing.T) {
	got, err := AddInt64(10, 20)
	if err != nil {
		t.Fatalf("AddInt64 returned unexpected error: %v", err)
	}
	if got != 30 {
		t.Fatalf("AddInt64 = %d, want 30", got)
	}
	if _, err := AddInt64(math.MaxInt64, 1); err == nil {
		t.Fatal("AddInt64 should reject overflow")
	}
}

func TestDiffUint64ToInt64(t *testing.T) {
	got, err := DiffUint64ToInt64(20, 8)
	if err != nil {
		t.Fatalf("DiffUint64ToInt64 returned unexpected error: %v", err)
	}
	if got != 12 {
		t.Fatalf("DiffUint64ToInt64 = %d, want 12", got)
	}

	got, err = DiffUint64ToInt64(8, 20)
	if err != nil {
		t.Fatalf("DiffUint64ToInt64 returned unexpected error: %v", err)
	}
	if got != -12 {
		t.Fatalf("DiffUint64ToInt64 = %d, want -12", got)
	}

	if _, err := DiffUint64ToInt64(math.MaxUint64, 0); err == nil {
		t.Fatal("DiffUint64ToInt64 should reject overflow")
	}
}

func TestSubInt64(t *testing.T) {
	got, err := SubInt64(10, 3)
	if err != nil {
		t.Fatalf("SubInt64 returned unexpected error: %v", err)
	}
	if got != 7 {
		t.Fatalf("SubInt64 = %d, want 7", got)
	}
	if _, err := SubInt64(math.MinInt64, 1); err == nil {
		t.Fatal("SubInt64 should reject underflow")
	}
}

func TestAddInt32(t *testing.T) {
	got, err := AddInt32(10, 20)
	if err != nil {
		t.Fatalf("AddInt32 returned unexpected error: %v", err)
	}
	if got != 30 {
		t.Fatalf("AddInt32 = %d, want 30", got)
	}
	if _, err := AddInt32(math.MaxInt32, 1); err == nil {
		t.Fatal("AddInt32 should reject overflow")
	}
}

func TestSubInt32(t *testing.T) {
	got, err := SubInt32(10, 3)
	if err != nil {
		t.Fatalf("SubInt32 returned unexpected error: %v", err)
	}
	if got != 7 {
		t.Fatalf("SubInt32 = %d, want 7", got)
	}
	if _, err := SubInt32(math.MinInt32, 1); err == nil {
		t.Fatal("SubInt32 should reject underflow")
	}
	got, err = SubInt32(-1, math.MinInt32)
	if err != nil {
		t.Fatalf("SubInt32 returned unexpected error for -1 - MinInt32: %v", err)
	}
	if got != math.MaxInt32 {
		t.Fatalf("SubInt32 = %d, want %d", got, math.MaxInt32)
	}
	got, err = SubInt32(math.MinInt32, math.MinInt32)
	if err != nil {
		t.Fatalf("SubInt32 returned unexpected error for MinInt32 - MinInt32: %v", err)
	}
	if got != 0 {
		t.Fatalf("SubInt32 = %d, want 0", got)
	}
	if _, err := SubInt32(0, math.MinInt32); err == nil {
		t.Fatal("SubInt32 should reject overflow")
	}
}

func TestAddUint64(t *testing.T) {
	got, err := AddUint64(7, 8)
	if err != nil {
		t.Fatalf("AddUint64 returned unexpected error: %v", err)
	}
	if got != 15 {
		t.Fatalf("AddUint64 = %d, want 15", got)
	}
	if _, err := AddUint64(math.MaxUint64, 1); err == nil {
		t.Fatal("AddUint64 should reject overflow")
	}
}

func TestMulInt64(t *testing.T) {
	got, err := MulInt64(7, 8)
	if err != nil {
		t.Fatalf("MulInt64 returned unexpected error: %v", err)
	}
	if got != 56 {
		t.Fatalf("MulInt64 = %d, want 56", got)
	}

	got, err = MulInt64(-7, 8)
	if err != nil {
		t.Fatalf("MulInt64 returned unexpected error: %v", err)
	}
	if got != -56 {
		t.Fatalf("MulInt64 = %d, want -56", got)
	}

	if _, err := MulInt64(math.MaxInt64, 2); err == nil {
		t.Fatal("MulInt64 should reject overflow")
	}
	if _, err := MulInt64(math.MinInt64, -1); err == nil {
		t.Fatal("MulInt64 should reject math.MinInt64 * -1")
	}
}

func TestMulInt32(t *testing.T) {
	got, err := MulInt32(7, 8)
	if err != nil {
		t.Fatalf("MulInt32 returned unexpected error: %v", err)
	}
	if got != 56 {
		t.Fatalf("MulInt32 = %d, want 56", got)
	}

	got, err = MulInt32(-7, 8)
	if err != nil {
		t.Fatalf("MulInt32 returned unexpected error: %v", err)
	}
	if got != -56 {
		t.Fatalf("MulInt32 = %d, want -56", got)
	}

	if _, err := MulInt32(math.MaxInt32, 2); err == nil {
		t.Fatal("MulInt32 should reject overflow")
	}
	if _, err := MulInt32(math.MinInt32, -1); err == nil {
		t.Fatal("MulInt32 should reject math.MinInt32 * -1")
	}
}

func TestMulUint64(t *testing.T) {
	got, err := MulUint64(7, 8)
	if err != nil {
		t.Fatalf("MulUint64 returned unexpected error: %v", err)
	}
	if got != 56 {
		t.Fatalf("MulUint64 = %d, want 56", got)
	}
	if _, err := MulUint64(math.MaxUint64, 2); err == nil {
		t.Fatal("MulUint64 should reject overflow")
	}
}

func TestIncInt(t *testing.T) {
	got, err := IncInt(9)
	if err != nil {
		t.Fatalf("IncInt returned unexpected error: %v", err)
	}
	if got != 10 {
		t.Fatalf("IncInt = %d, want 10", got)
	}
	if _, err := IncInt(math.MaxInt); err == nil {
		t.Fatal("IncInt should reject overflow")
	}
}

func TestAbsInt64ToUint64(t *testing.T) {
	got, err := AbsInt64ToUint64(-12)
	if err != nil {
		t.Fatalf("AbsInt64ToUint64 returned unexpected error: %v", err)
	}
	if got != 12 {
		t.Fatalf("AbsInt64ToUint64 = %d, want 12", got)
	}
	if _, err := AbsInt64ToUint64(math.MinInt64); err == nil {
		t.Fatal("AbsInt64ToUint64 should reject math.MinInt64")
	}
}
