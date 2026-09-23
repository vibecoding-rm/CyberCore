-- Evidence is append-only: once sealed by the broker it can never be changed
-- or removed through normal SQL. Only a superuser disabling triggers
-- (session_replication_role = replica) can bypass this, and get_evidence()
-- still re-verifies the SHA-256 on every read.
CREATE OR REPLACE FUNCTION cybercore_reject_evidence_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'La tabla evidence es de sólo inserción: % no permitido', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

DROP TRIGGER IF EXISTS evidence_append_only ON evidence;
CREATE TRIGGER evidence_append_only
    BEFORE UPDATE OR DELETE ON evidence
    FOR EACH ROW EXECUTE FUNCTION cybercore_reject_evidence_change();

DROP TRIGGER IF EXISTS evidence_no_truncate ON evidence;
CREATE TRIGGER evidence_no_truncate
    BEFORE TRUNCATE ON evidence
    FOR EACH STATEMENT EXECUTE FUNCTION cybercore_reject_evidence_change();
