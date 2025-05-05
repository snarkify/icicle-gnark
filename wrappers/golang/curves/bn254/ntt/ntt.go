package ntt

// #cgo CFLAGS: -I./include/
// #include "ntt.h"
import "C"

import (
	"fmt"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/consensys/gnark/logger"
	"github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/core"
	bn254 "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/curves/bn254"
	"github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
)

var nttOperationsCounter uint64 = 0

func Ntt[T any](scalars core.HostOrDeviceSlice, dir core.NTTDir, cfg *core.NTTConfig[T], results core.HostOrDeviceSlice) runtime.EIcicleError {
	scalarsPointer, resultsPointer, size, cfgPointer := core.NttCheck[T](scalars, cfg, results)

	// Log operation count and dimensions
	count := atomic.AddUint64(&nttOperationsCounter, 1)
	var direction string
	if dir == core.KForward {
		direction = "forward"
	} else {
		direction = "inverse"
	}
	dimensions := fmt.Sprintf("size: %d, direction: %s", size, direction)
	log := logger.Logger()
	log.Debug().Uint64("count", count).Str("operation", "BN254_NTT").Str("dimensions", dimensions).Msg("ICICLE Operation")

	// Start timing
	start := time.Now()

	cScalars := (*C.scalar_t)(scalarsPointer)
	cSize := (C.int)(size)
	cDir := (C.int)(dir)
	cCfg := (*C.NTTConfig)(cfgPointer)
	cResults := (*C.scalar_t)(resultsPointer)

	__ret := C.bn254_ntt(cScalars, cSize, cDir, cCfg, cResults)
	err := runtime.EIcicleError(__ret)

	// End timing and log
	elapsed := time.Since(start)
	log.Debug().
		Uint64("count", count).
		Str("operation", "BN254_NTT").
		Str("dimensions", dimensions).
		Float64("duration_ms", float64(elapsed.Microseconds())/1000.0).
		Msg("ICICLE Operation Time")

	return err
}

func GetDefaultNttConfig() core.NTTConfig[[bn254.SCALAR_LIMBS]uint32] {
	cosetGenField := bn254.ScalarField{}
	cosetGenField.One()
	var cosetGen [bn254.SCALAR_LIMBS]uint32
	for i, v := range cosetGenField.GetLimbs() {
		cosetGen[i] = v
	}

	return core.GetDefaultNTTConfig(cosetGen)
}

func GetRootOfUnity(size uint64) bn254.ScalarField {
	cRes := C.bn254_get_root_of_unity((C.size_t)(size))
	var res bn254.ScalarField
	res.FromLimbs(*(*[]uint32)(unsafe.Pointer(cRes)))
	return res
}

func InitDomain(primitiveRoot bn254.ScalarField, cfg core.NTTInitDomainConfig) runtime.EIcicleError {
	// Log operation count
	count := atomic.AddUint64(&nttOperationsCounter, 1)
	dimensions := fmt.Sprintf("max_size: %d", cfg.MaxSize)
	log := logger.Logger()
	log.Debug().Uint64("count", count).Str("operation", "BN254_NTT_INIT_DOMAIN").Str("dimensions", dimensions).Msg("ICICLE Operation")

	// Start timing
	start := time.Now()

	cPrimitiveRoot := (*C.scalar_t)(unsafe.Pointer(primitiveRoot.AsPointer()))
	cCfg := (*C.NTTInitDomainConfig)(unsafe.Pointer(&cfg))
	__ret := C.bn254_ntt_init_domain(cPrimitiveRoot, cCfg)
	err := runtime.EIcicleError(__ret)

	// End timing and log
	elapsed := time.Since(start)
	log.Debug().
		Uint64("count", count).
		Str("operation", "BN254_NTT_INIT_DOMAIN").
		Str("dimensions", dimensions).
		Float64("duration_ms", float64(elapsed.Microseconds())/1000.0).
		Msg("ICICLE Operation Time")

	return err
}

func ReleaseDomain() runtime.EIcicleError {
	// Log operation count
	count := atomic.AddUint64(&nttOperationsCounter, 1)
	log := logger.Logger()
	log.Debug().Uint64("count", count).Str("operation", "BN254_NTT_RELEASE_DOMAIN").Msg("ICICLE Operation")

	// Start timing
	start := time.Now()

	__ret := C.bn254_ntt_release_domain()
	err := runtime.EIcicleError(__ret)

	// End timing and log
	elapsed := time.Since(start)
	log.Debug().
		Uint64("count", count).
		Str("operation", "BN254_NTT_RELEASE_DOMAIN").
		Float64("duration_ms", float64(elapsed.Microseconds())/1000.0).
		Msg("ICICLE Operation Time")

	return err
}
