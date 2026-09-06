DO $$
BEGIN
    RAISE EXCEPTION 'audit detail redaction migration is forward-only';
END $$;
