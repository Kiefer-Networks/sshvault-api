-- Replay evidence and pending admission state cannot be safely discarded.
DO $$ BEGIN
    RAISE EXCEPTION 'authentication replay/admission migration is forward-only';
END $$;
