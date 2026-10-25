package probetarget

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"mibee-steward/internal/changedetect"
)

func TestTransitionDetector_ThresholdBeforeFailing(t *testing.T) {
	d := newTransitionDetector()

	// two failures: below threshold, nothing emits, still not failing
	assert.Empty(t, d.observe(1, "success", "fail"))
	assert.Empty(t, d.observe(1, "success", "timeout"))
	// third failure crosses the threshold
	assert.Equal(t, changedetect.ChangeTypeProbeFailed, d.observe(1, "success", "fail"))
	// further failures are not transitions
	assert.Empty(t, d.observe(1, "success", "fail"))
}

func TestTransitionDetector_StreakResetsOnSuccess(t *testing.T) {
	d := newTransitionDetector()

	assert.Empty(t, d.observe(1, "success", "fail"))
	assert.Empty(t, d.observe(1, "success", "fail"))
	// a success mid-streak resets the counter, not a recovery (was never failing)
	assert.Empty(t, d.observe(1, "success", "success"))
	assert.Empty(t, d.observe(1, "success", "fail"))
	assert.Empty(t, d.observe(1, "success", "fail"))
	// only the third consecutive failure fires
	assert.Equal(t, changedetect.ChangeTypeProbeFailed, d.observe(1, "success", "fail"))
}

func TestTransitionDetector_RecoveryEmitsOnce(t *testing.T) {
	d := newTransitionDetector()

	for i := 0; i < probeFailedThreshold; i++ {
		d.observe(1, "success", "fail")
	}
	assert.Equal(t, changedetect.ChangeTypeProbeRecovered, d.observe(1, "success", "success"))
	// further successes are not transitions
	assert.Empty(t, d.observe(1, "success", "success"))
}

func TestTransitionDetector_RestartSeedsFromPersistedStateSilently(t *testing.T) {
	d := newTransitionDetector()

	// first sight with persisted failing state: adopt WITHOUT emitting
	assert.Empty(t, d.observe(1, "fail", "fail"))
	// recovery still emits normally
	assert.Equal(t, changedetect.ChangeTypeProbeRecovered, d.observe(1, "fail", "success"))
}

func TestTransitionDetector_PruneDropsAbsentTargets(t *testing.T) {
	d := newTransitionDetector()

	d.observe(1, "success", "fail")
	d.observe(2, "success", "fail")

	d.prune(map[int64]bool{1: true})

	// target 2 restarts from scratch (state gone): streak 1 again, below threshold
	assert.Empty(t, d.observe(2, "success", "fail"))
	// target 1 kept its pre-prune streak (1): needs threshold-1 more failures
	assert.Empty(t, d.observe(1, "success", "fail"))
	assert.Equal(t, changedetect.ChangeTypeProbeFailed, d.observe(1, "success", "fail"))
}
