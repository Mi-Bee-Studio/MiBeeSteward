package probetarget

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"mibee-steward/internal/changedetect"
)

func TestTransitionDetector_ThresholdBeforeFailing(t *testing.T) {
	d := newTransitionDetector()

	// two failures: below threshold, nothing emits, still not failing
	assert.Empty(t, d.observe(1, "center", "success", "fail"))
	assert.Empty(t, d.observe(1, "center", "success", "timeout"))
	// third failure crosses the threshold
	assert.Equal(t, changedetect.ChangeTypeProbeFailed, d.observe(1, "center", "success", "fail"))
	// further failures are not transitions
	assert.Empty(t, d.observe(1, "center", "success", "fail"))
}

func TestTransitionDetector_StreakResetsOnSuccess(t *testing.T) {
	d := newTransitionDetector()

	assert.Empty(t, d.observe(1, "center", "success", "fail"))
	assert.Empty(t, d.observe(1, "center", "success", "fail"))
	// a success mid-streak resets the counter, not a recovery (was never failing)
	assert.Empty(t, d.observe(1, "center", "success", "success"))
	assert.Empty(t, d.observe(1, "center", "success", "fail"))
	assert.Empty(t, d.observe(1, "center", "success", "fail"))
	// only the third consecutive failure fires
	assert.Equal(t, changedetect.ChangeTypeProbeFailed, d.observe(1, "center", "success", "fail"))
}

func TestTransitionDetector_RecoveryEmitsOnce(t *testing.T) {
	d := newTransitionDetector()

	for i := 0; i < probeFailedThreshold; i++ {
		d.observe(1, "center", "success", "fail")
	}
	assert.Equal(t, changedetect.ChangeTypeProbeRecovered, d.observe(1, "center", "success", "success"))
	// further successes are not transitions
	assert.Empty(t, d.observe(1, "center", "success", "success"))
}

func TestTransitionDetector_RestartSeedsFromPersistedStateSilently(t *testing.T) {
	d := newTransitionDetector()

	// first sight with persisted failing state: adopt WITHOUT emitting
	assert.Empty(t, d.observe(1, "center", "fail", "fail"))
	// recovery still emits normally
	assert.Equal(t, changedetect.ChangeTypeProbeRecovered, d.observe(1, "center", "fail", "success"))
}

// TestTransitionDetector_TracksAreIndependentPerVantage: the center track and
// an agent track hold separate liveness states — an agent whose network path
// to the target is dead declares its own failure while the center track never
// leaves ok.
func TestTransitionDetector_TracksAreIndependentPerVantage(t *testing.T) {
	d := newTransitionDetector()

	agent := "agent:lan-63"
	for i := 0; i < probeFailedThreshold-1; i++ {
		assert.Empty(t, d.observe(1, agent, "", "fail"))
		assert.Empty(t, d.observe(1, "center", "", "success"))
	}
	// the agent track crosses its threshold; the center track stays quiet
	assert.Equal(t, changedetect.ChangeTypeProbeFailed, d.observe(1, agent, "", "fail"))
	assert.Empty(t, d.observe(1, "center", "", "success"))

	// recovery is equally per-track
	assert.Equal(t, changedetect.ChangeTypeProbeRecovered, d.observe(1, agent, "", "success"))
}

func TestTransitionDetector_PruneDropsAbsentTargets(t *testing.T) {
	d := newTransitionDetector()

	d.observe(1, "center", "success", "fail")
	d.observe(2, "center", "success", "fail")
	d.observe(2, "agent:x", "", "fail")

	// target 2 disappears entirely: ALL its tracks go, both vantages
	d.prune(map[int64]bool{1: true})
	d.observe(2, "agent:x", "", "fail") // first sight again after prune
	d.observe(2, "center", "success", "fail")

	// target 1 kept its streak: needs threshold-1 more failures
	assert.Empty(t, d.observe(1, "center", "success", "fail"))
	assert.Equal(t, changedetect.ChangeTypeProbeFailed, d.observe(1, "center", "success", "fail"))
}
