--
-- PostgreSQL database dump (fixture — not a real estate's schema)
--

CREATE TABLE public.meetings (
    id integer NOT NULL,
    user_id integer NOT NULL,
    platform character varying(50) NOT NULL,
    platform_specific_id character varying(255),
    status character varying(50) DEFAULT 'requested'::character varying NOT NULL
);

CREATE TABLE public.api_tokens (
    id integer NOT NULL,
    user_id integer NOT NULL,
    token character varying(255) NOT NULL,
    scopes jsonb DEFAULT '[]'::jsonb NOT NULL
);

CREATE INDEX ix_meetings_status ON public.meetings USING btree (status);

-- A credential that has no business being in a schema dump, and the reason
-- redact_text exists: both of these lose their value before the file is written.
ALTER ROLE vexa SET app.api_token = 'tok-should-be-redacted-42';

CREATE SERVER analytics_mirror FOREIGN DATA WRAPPER postgres_fdw
  OPTIONS (host 'analytics.internal', dbname 'vexa', password 'fdw-secret-value-9999');
