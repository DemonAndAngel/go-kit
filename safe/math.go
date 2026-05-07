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

func AddInt32(a, b int32) (int32, error) {
	if b > 0 && a > math.MaxInt32-b {
		return 0, errors.New("int32 overflow")
	}
	if b < 0 && a < math.MinInt32-b {
		return 0, errors.New("int32 underflow")
	}
	return a + b, nil
}

func SubInt32(a, b int32) (int32, error) {
	v, err := SubInt64(int64(a), int64(b))
	if err != nil {
		return 0, err
	}
	if v > math.MaxInt32 {
		return 0, errors.New("int32 overflow")
	}
	if v < math.MinInt32 {
		return 0, errors.New("int32 underflow")
	}
	return int32(v), nil
}

func AddUint64(a, b uint64) (uint64, error) {
	if a > math.MaxUint64-b {
		return 0, errors.New("uint64 overflow")
	}
	return a + b, nil
}

func MulUint64(a, b uint64) (uint64, error) {
	if a == 0 || b == 0 {
		return 0, nil
	}
	if a > math.MaxUint64/b {
		return 0, errors.New("uint64 overflow")
	}
	return a * b, nil
}

func MulInt64(a, b int64) (int64, error) {
	if a == 0 || b == 0 {
		return 0, nil
	}
	if a == -1 && b == math.MinInt64 {
		return 0, errors.New("int64 overflow")
	}
	if b == -1 && a == math.MinInt64 {
		return 0, errors.New("int64 overflow")
	}
	if a > 0 {
		if b > 0 {
			if a > math.MaxInt64/b {
				return 0, errors.New("int64 overflow")
			}
		} else {
			if b < math.MinInt64/a {
				return 0, errors.New("int64 underflow")
			}
		}
	} else {
		if b > 0 {
			if a < math.MinInt64/b {
				return 0, errors.New("int64 underflow")
			}
		} else {
			if a < math.MaxInt64/b {
				return 0, errors.New("int64 overflow")
			}
		}
	}
	return a * b, nil
}

func MulInt32(a, b int32) (int32, error) {
	if a == 0 || b == 0 {
		return 0, nil
	}
	if a == -1 && b == math.MinInt32 {
		return 0, errors.New("int32 overflow")
	}
	if b == -1 && a == math.MinInt32 {
		return 0, errors.New("int32 overflow")
	}
	if a > 0 {
		if b > 0 {
			if a > math.MaxInt32/b {
				return 0, errors.New("int32 overflow")
			}
		} else {
			if b < math.MinInt32/a {
				return 0, errors.New("int32 underflow")
			}
		}
	} else {
		if b > 0 {
			if a < math.MinInt32/b {
				return 0, errors.New("int32 underflow")
			}
		} else {
			if a < math.MaxInt32/b {
				return 0, errors.New("int32 overflow")
			}
		}
	}
	return a * b, nil
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

func ModInt64(a, b int64) int64 {
	return a % b
}

func Floor(x float64) float64 {
	return math.Floor(x)
}
