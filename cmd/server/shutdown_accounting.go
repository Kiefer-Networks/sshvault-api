package main

import "github.com/rs/zerolog"

type unconfirmedWork interface {
	Unconfirmed() int64
}

// reportShutdownLosses takes non-waiting snapshots. Counts describe work whose
// success has not been confirmed at this instant, not guaranteed permanent loss.
func reportShutdownLosses(logger zerolog.Logger, auditWork, mailWork unconfirmedWork) {
	entries, messages := auditWork.Unconfirmed(), mailWork.Unconfirmed()
	if entries > 0 || messages > 0 {
		logger.Error().Int64("unconfirmed_entries", entries).
			Int64("unconfirmed_messages", messages).
			Msg("shutdown work not confirmed completed")
	}
}
