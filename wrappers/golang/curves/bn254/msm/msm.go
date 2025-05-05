package msm

// #cgo CFLAGS: -I./include/
// #include "msm.h"
import "C"

import (
	"fmt"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/consensys/gnark/logger"
	"github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/core"
	"github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
)

var msmOperationsCounter uint64 = 0

func GetDefaultMSMConfig() core.MSMConfig {
	return core.GetDefaultMSMConfig()
}

func Msm(scalars core.HostOrDeviceSlice, points core.HostOrDeviceSlice, cfg *core.MSMConfig, results core.HostOrDeviceSlice) runtime.EIcicleError {
	scalarsPointer, pointsPointer, resultsPointer, size := core.MsmCheck(scalars, points, cfg, results)

	// Log operation count and dimensions
	count := atomic.AddUint64(&msmOperationsCounter, 1)
	dimensions := fmt.Sprintf("scalars: %d, points: %d", size, size)
	log := logger.Logger()
	log.Debug().Uint64("count", count).Str("operation", "BN254_MSM").Str("dimensions", dimensions).Msg("ICICLE Operation")


	cScalars := (*C.scalar_t)(scalarsPointer)
	cPoints := (*C.affine_t)(pointsPointer)
	cResults := (*C.projective_t)(resultsPointer)
	cSize := (C.int)(size)
	cCfg := (*C.MSMConfig)(unsafe.Pointer(cfg))

	// Start timing
	start := time.Now()
	__ret := C.bn254_msm(cScalars, cPoints, cSize, cCfg, cResults)
	err := runtime.EIcicleError(__ret)

	// End timing and log
	elapsed := time.Since(start)
	log.Debug().
		Uint64("count", count).
		Str("operation", "BN254_MSM").
		Str("dimensions", dimensions).
		Float64("duration_ms", float64(elapsed.Microseconds())/1000.0).
		Msg("ICICLE Operation Time")

	return err
}

func PrecomputeBases(bases core.HostOrDeviceSlice, cfg *core.MSMConfig, outputBases core.DeviceSlice) runtime.EIcicleError {
	basesPointer, outputBasesPointer := core.PrecomputeBasesCheck(bases, cfg, outputBases)

	// Log operation count 
	count := atomic.AddUint64(&msmOperationsCounter, 1)
	var basesLen int
	if cfg.ArePointsSharedInBatch {
		basesLen = bases.Len()
	} else {
		basesLen = bases.Len() / int(cfg.BatchSize)
	}
	dimensions := fmt.Sprintf("bases: %d", basesLen)
	log := logger.Logger()
	log.Debug().Uint64("count", count).Str("operation", "BN254_MSM_PRECOMPUTE").Str("dimensions", dimensions).Msg("ICICLE Operation")

	// Start timing

	cBases := (*C.affine_t)(basesPointer)
	var cBasesLen C.int
	if cfg.ArePointsSharedInBatch {
		cBasesLen = (C.int)(bases.Len())
	} else {
		cBasesLen = (C.int)(bases.Len() / int(cfg.BatchSize))
	}
	cCfg := (*C.MSMConfig)(unsafe.Pointer(cfg))
	cOutputBases := (*C.affine_t)(outputBasesPointer)

	start := time.Now()
	__ret := C.bn254_msm_precompute_bases(cBases, cBasesLen, cCfg, cOutputBases)
	err := runtime.EIcicleError(__ret)

	// End timing and log
	elapsed := time.Since(start)
	log.Debug().
		Uint64("count", count).
		Str("operation", "BN254_MSM_PRECOMPUTE").
		Str("dimensions", dimensions).
		Float64("duration_ms", float64(elapsed.Microseconds())/1000.0).
		Msg("ICICLE Operation Time")

	return err
}
