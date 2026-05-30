// Package clock defines the shared time source abstraction.
package clock

import "time"

// Clock returns the current time.
type Clock func() time.Time

// System returns the current wall-clock time.
func System() time.Time {
	return time.Now()
}

// OrSystem returns now, or the system clock when now is nil.
func OrSystem(now Clock) Clock {
	if now == nil {
		return System
	}

	return now
}
