package safe

import (
	"errors"
	"github.com/spf13/cast"
	"math"
)

// ToInt64 安全地将接口转换为 int64
func ToInt64(i interface{}) int64 {
	return cast.ToInt64(i)
}

// ToInt 安全地将接口转换为 int
func ToInt(i interface{}) int {
	return cast.ToInt(i)
}

// DiffUint64 安全地计算两个 uint64 的差值并转为 int64
func DiffUint64(a, b uint64) int64 {
	if a >= b {
		return cast.ToInt64(a - b)
	}
	return -cast.ToInt64(b - a)
}

func DiffUint64ToInt64(a, b uint64) (int64, error) {
	if a >= b {
		diff := a - b
		if diff > math.MaxInt64 {
			return 0, errors.New("uint64 diff overflows int64")
		}
		return int64(diff), nil
	}

	diff := b - a
	if diff > math.MaxInt64 {
		return 0, errors.New("uint64 diff overflows int64")
	}
	return SubInt64(0, int64(diff))
}

func AddInt64(a, b int64) (int64, error) {
	if b > 0 && a > math.MaxInt64-b {
		return 0, errors.New("int64 overflow")
	}
	if b < 0 && a < math.MinInt64-b {
		return 0, errors.New("int64 underflow")
	}
	return a + b, nil
}

func SubInt64(a, b int64) (int64, error) {
	if b == math.MinInt64 {
		return 0, errors.New("int64 underflow")
	}
	return AddInt64(a, -b)
}

func AddUint64(a, b uint64) (uint64, error) {
	if a > math.MaxUint64-b {
		return 0, errors.New("uint64 overflow")
	}
	return a + b, nil
}

func IncInt(v int) (int, error) {
	if v == math.MaxInt {
		return 0, errors.New("int overflow")
	}
	return v + 1, nil
}

func AbsInt64ToUint64(v int64) (uint64, error) {
	if v == math.MinInt64 {
		return 0, errors.New("int64 absolute overflow")
	}
	if v < 0 {
		return uint64(-v), nil
	}
	return uint64(v), nil
}
