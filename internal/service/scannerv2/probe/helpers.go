package probe

import (
	"strconv"
)

// timeMsString formats a millisecond value as a trimmed decimal string with no
// trailing zeros (e.g. 1.5ms → "1.5", 2ms → "2"). Used for Evidence RawData.
func timeMsString(ms int64) string {
	// strconv.FormatInt gives whole ms; if sub-ms precision matters elsewhere
	// the caller can store the raw duration. For RTT we round to ms.
	return strconv.FormatInt(ms, 10)
}
