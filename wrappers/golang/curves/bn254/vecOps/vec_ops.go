package vecOps

// #cgo CFLAGS: -I./include/
// #include "vec_ops.h"
import "C"

import (
	"fmt"
	"sync/atomic"

	"github.com/consensys/gnark/logger"
	"github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/core"
	"github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
)

var vecOpsOperationsCounter uint64 = 0

func VecOp(a, b, out core.HostOrDeviceSlice, config core.VecOpsConfig, op core.VecOps) (ret runtime.EIcicleError) {
	aPointer, bPointer, outPointer, cfgPointer, size := core.VecOpCheck(a, b, out, &config)

	// Log operation count and dimensions
	count := atomic.AddUint64(&vecOpsOperationsCounter, 1)
	var operation string
	switch op {
	case core.Sub:
		operation = "SUB"
	case core.Add:
		operation = "ADD"
	case core.Mul:
		operation = "MUL"
	}
	dimensions := fmt.Sprintf("size: %d, operation: %s", size, operation)
	log := logger.Logger()
	log.Debug().Uint64("count", count).Str("operation", "BN254_VECOP").Str("dimensions", dimensions).Msg("ICICLE Operation")

	cA := (*C.scalar_t)(aPointer)
	cB := (*C.scalar_t)(bPointer)
	cOut := (*C.scalar_t)(outPointer)
	cConfig := (*C.VecOpsConfig)(cfgPointer)
	cSize := (C.int)(size)

	switch op {
	case core.Sub:
		ret = (runtime.EIcicleError)(C.bn254_vector_sub(cA, cB, cSize, cConfig, cOut))
	case core.Add:
		ret = (runtime.EIcicleError)(C.bn254_vector_add(cA, cB, cSize, cConfig, cOut))
	case core.Mul:
		ret = (runtime.EIcicleError)(C.bn254_vector_mul(cA, cB, cSize, cConfig, cOut))
	}

	return ret
}
