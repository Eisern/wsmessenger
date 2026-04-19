--
-- WS Messenger — PostgreSQL schema (public release)
--
-- Apply once on a fresh database before starting the server:
--   createdb chatdb
--   psql -d chatdb -f server/schema.sql
--
-- The server itself does NOT auto-create base tables on startup; only a few
-- archive/migration tables are lazily ensured at runtime (see
-- server/main.py: chat_room_key_archive, chat_dm_key_archive,
-- chat_dm_delete_requests). Everything else must exist before first request.
--

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: admin_audit; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.admin_audit (
    id bigint NOT NULL,
    ts timestamp with time zone DEFAULT now() NOT NULL,
    actor_id bigint,
    actor text NOT NULL,
    action text NOT NULL,
    target text NOT NULL,
    ok boolean NOT NULL,
    ip text DEFAULT ''::text NOT NULL,
    ua text DEFAULT ''::text NOT NULL,
    meta jsonb DEFAULT '{}'::jsonb NOT NULL
);


--
-- Name: admin_audit_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.admin_audit_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: admin_audit_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.admin_audit_id_seq OWNED BY public.admin_audit.id;


--
-- Name: admin_users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.admin_users (
    user_id bigint NOT NULL,
    role text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT admin_users_role_check CHECK ((role = ANY (ARRAY['admin'::text, 'superadmin'::text])))
);


--
-- Name: chat_dm_delete_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_dm_delete_requests (
    thread_id bigint NOT NULL,
    requester_id bigint NOT NULL,
    scope character varying(16) NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: chat_dm_delivery; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_dm_delivery (
    thread_id bigint NOT NULL,
    delivery_secret bytea NOT NULL,
    rotated_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone DEFAULT (now() + '24:00:00'::interval) NOT NULL
);


--
-- Name: chat_dm_key_archive; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_dm_key_archive (
    thread_id integer NOT NULL,
    user_id integer NOT NULL,
    key_id character varying(64) NOT NULL,
    encrypted_thread_key text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: chat_dm_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_dm_members (
    thread_id bigint NOT NULL,
    user_id bigint NOT NULL,
    joined_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: chat_dm_messages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_dm_messages (
    id bigint NOT NULL,
    thread_id bigint NOT NULL,
    user_id bigint,
    text text NOT NULL,
    ts timestamp with time zone DEFAULT now() NOT NULL,
    e2ee_v integer,
    e2ee_alg text,
    e2ee_iv text,
    e2ee_ct text,
    e2ee_sender_kid text,
    e2ee_peer_kid text,
    is_sealed boolean DEFAULT false NOT NULL
);


--
-- Name: chat_dm_messages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.chat_dm_messages_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: chat_dm_messages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.chat_dm_messages_id_seq OWNED BY public.chat_dm_messages.id;


--
-- Name: chat_dm_pairs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_dm_pairs (
    user_low bigint NOT NULL,
    user_high bigint NOT NULL,
    thread_id bigint NOT NULL
);


--
-- Name: chat_dm_thread_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_dm_thread_keys (
    thread_id integer NOT NULL,
    user_id integer NOT NULL,
    encrypted_thread_key text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: chat_dm_threads; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_dm_threads (
    id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_message_at timestamp with time zone
);


--
-- Name: chat_dm_threads_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.chat_dm_threads_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: chat_dm_threads_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.chat_dm_threads_id_seq OWNED BY public.chat_dm_threads.id;


--
-- Name: chat_dm_ud_nonces; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_dm_ud_nonces (
    thread_id bigint NOT NULL,
    nonce bytea NOT NULL,
    ts bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: chat_feedback; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_feedback (
    id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    user_id bigint NOT NULL,
    username text DEFAULT ''::text NOT NULL,
    ip inet,
    ua text DEFAULT ''::text NOT NULL,
    meta_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    message text NOT NULL,
    CONSTRAINT chat_feedback_message_len_chk CHECK (((char_length(message) >= 1) AND (char_length(message) <= 1200))),
    CONSTRAINT chat_feedback_ua_len_chk CHECK ((char_length(ua) <= 400)),
    CONSTRAINT chat_feedback_username_len_chk CHECK ((char_length(username) <= 80))
);


--
-- Name: chat_feedback_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.chat_feedback_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: chat_feedback_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.chat_feedback_id_seq OWNED BY public.chat_feedback.id;


--
-- Name: chat_files; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_files (
    id bigint NOT NULL,
    token text NOT NULL,
    room_id bigint,
    uploader_user_id bigint NOT NULL,
    original_name text NOT NULL,
    content_type text,
    size_bytes bigint NOT NULL,
    storage_path text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    thread_id bigint
);


--
-- Name: chat_files_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.chat_files_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: chat_files_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.chat_files_id_seq OWNED BY public.chat_files.id;


--
-- Name: chat_friendships; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_friendships (
    id bigint NOT NULL,
    requester_id bigint NOT NULL,
    addressee_id bigint NOT NULL,
    status text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    responded_at timestamp with time zone,
    CONSTRAINT chat_friendships_check CHECK ((requester_id <> addressee_id)),
    CONSTRAINT chat_friendships_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'accepted'::text, 'declined'::text, 'blocked'::text])))
);


--
-- Name: chat_friendships_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.chat_friendships_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: chat_friendships_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.chat_friendships_id_seq OWNED BY public.chat_friendships.id;


--
-- Name: chat_messages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_messages (
    id bigint NOT NULL,
    room text,
    username text,
    text text NOT NULL,
    ts timestamp with time zone DEFAULT now() NOT NULL,
    user_id bigint NOT NULL,
    room_id bigint NOT NULL,
    encrypted_iv text,
    is_encrypted boolean DEFAULT false
);


--
-- Name: chat_messages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.chat_messages_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: chat_messages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.chat_messages_id_seq OWNED BY public.chat_messages.id;


--
-- Name: chat_room_key_archive; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_room_key_archive (
    room_id bigint NOT NULL,
    user_id bigint NOT NULL,
    key_id character varying(64) NOT NULL,
    encrypted_room_key text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: chat_room_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_room_keys (
    id bigint NOT NULL,
    room_id bigint NOT NULL,
    user_id bigint NOT NULL,
    encrypted_room_key text NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: TABLE chat_room_keys; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.chat_room_keys IS 'Stores encrypted room keys for each user (encrypted with user public key)';


--
-- Name: chat_room_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.chat_room_keys_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: chat_room_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.chat_room_keys_id_seq OWNED BY public.chat_room_keys.id;


--
-- Name: chat_room_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_room_members (
    room_id bigint NOT NULL,
    user_id bigint NOT NULL,
    role text DEFAULT 'member'::text NOT NULL,
    invited_by bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    status text DEFAULT 'accepted'::text NOT NULL,
    CONSTRAINT chat_room_members_role_chk CHECK ((role = ANY (ARRAY['owner'::text, 'admin'::text, 'member'::text, 'readonly'::text])))
);


--
-- Name: chat_room_pins; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_room_pins (
    room_id bigint NOT NULL,
    created_by bigint NOT NULL,
    url text,
    text text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: chat_rooms; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_rooms (
    id bigint NOT NULL,
    owner_user_id bigint NOT NULL,
    name text NOT NULL,
    password_hash text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    alias text,
    encrypted_room_key text,
    is_public boolean DEFAULT false NOT NULL,
    join_policy text DEFAULT 'invite_only'::text NOT NULL,
    description text,
    logo_token text,
    logo_path text,
    meta_updated_at timestamp with time zone DEFAULT now() NOT NULL,
    is_frozen boolean DEFAULT false NOT NULL,
    frozen_reason text,
    frozen_at timestamp with time zone,
    is_readonly boolean DEFAULT false NOT NULL
);


--
-- Name: COLUMN chat_rooms.is_readonly; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.chat_rooms.is_readonly IS 'If true, only owner/admin can send messages; members are read-only';


--
-- Name: chat_rooms_id_seq1; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.chat_rooms_id_seq1
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: chat_rooms_id_seq1; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.chat_rooms_id_seq1 OWNED BY public.chat_rooms.id;


--
-- Name: chat_user_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_user_keys (
    user_id bigint NOT NULL,
    alg text NOT NULL,
    kid text NOT NULL,
    public_key text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    is_active boolean DEFAULT false NOT NULL,
    revoked_at timestamp with time zone,
    CONSTRAINT chat_user_keys_alg_chk CHECK ((alg = 'x25519'::text)),
    CONSTRAINT chat_user_keys_kid_chk CHECK ((kid ~ '^[0-9a-f]{1,64}$'::text))
);


--
-- Name: chat_user_profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_user_profiles (
    user_id bigint NOT NULL,
    about text DEFAULT ''::text NOT NULL,
    privacy jsonb DEFAULT '{"allow_dm_from_non_friends": false, "allow_group_invites_from_non_friends": false}'::jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: chat_users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_users (
    id bigint NOT NULL,
    username text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: chat_users_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.chat_users_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: chat_users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.chat_users_id_seq OWNED BY public.chat_users.id;


--
-- Name: refresh_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.refresh_tokens (
    jti text NOT NULL,
    user_id integer NOT NULL,
    family_id text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    replaced_by text
);


--
-- Name: reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.reports (
    id bigint NOT NULL,
    reporter_id bigint NOT NULL,
    target_type text NOT NULL,
    target_id bigint NOT NULL,
    reason text NOT NULL,
    comment text DEFAULT ''::text NOT NULL,
    status text DEFAULT 'new'::text NOT NULL,
    reviewer_id bigint,
    review_note text DEFAULT ''::text NOT NULL,
    reviewed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    reported_content jsonb,
    CONSTRAINT reports_reason_check CHECK ((reason = ANY (ARRAY['spam'::text, 'harassment'::text, 'hate_speech'::text, 'illegal_content'::text, 'impersonation'::text, 'other'::text]))),
    CONSTRAINT reports_status_check CHECK ((status = ANY (ARRAY['new'::text, 'in_review'::text, 'resolved'::text, 'dismissed'::text]))),
    CONSTRAINT reports_target_type_check CHECK ((target_type = ANY (ARRAY['user'::text, 'message'::text, 'room'::text])))
);


--
-- Name: reports_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.reports_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: reports_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.reports_id_seq OWNED BY public.reports.id;


--
-- Name: room_seen; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.room_seen (
    id integer NOT NULL,
    room_id integer NOT NULL,
    user_id integer NOT NULL,
    seen_at timestamp with time zone DEFAULT now()
);


--
-- Name: room_seen_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.room_seen_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: room_seen_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.room_seen_id_seq OWNED BY public.room_seen.id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id bigint NOT NULL,
    username text NOT NULL,
    password_hash text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    public_key text,
    totp_secret text,
    totp_pending_secret text,
    totp_backup_codes text,
    is_banned boolean DEFAULT false NOT NULL,
    banned_at timestamp with time zone,
    banned_reason text,
    recovery_key_hash text,
    recovery_nonce text,
    recovery_nonce_expires double precision,
    tokens_valid_after double precision,
    CONSTRAINT users_recovery_key_hash_chk CHECK (((recovery_key_hash IS NULL) OR (recovery_key_hash ~ '^[0-9a-f]{64}$'::text)))
);


--
-- Name: COLUMN users.totp_secret; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.users.totp_secret IS 'Active TOTP base32 secret. NULL means 2FA is disabled.';


--
-- Name: COLUMN users.totp_pending_secret; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.users.totp_pending_secret IS 'Pending TOTP secret during setup flow, before first code verification.';


--
-- Name: COLUMN users.totp_backup_codes; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.users.totp_backup_codes IS 'JSON array of one-time backup codes for 2FA recovery.';


--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.users_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: admin_audit id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_audit ALTER COLUMN id SET DEFAULT nextval('public.admin_audit_id_seq'::regclass);


--
-- Name: chat_dm_messages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_dm_messages ALTER COLUMN id SET DEFAULT nextval('public.chat_dm_messages_id_seq'::regclass);


--
-- Name: chat_dm_threads id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_dm_threads ALTER COLUMN id SET DEFAULT nextval('public.chat_dm_threads_id_seq'::regclass);


--
-- Name: chat_feedback id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_feedback ALTER COLUMN id SET DEFAULT nextval('public.chat_feedback_id_seq'::regclass);


--
-- Name: chat_files id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_files ALTER COLUMN id SET DEFAULT nextval('public.chat_files_id_seq'::regclass);


--
-- Name: chat_friendships id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_friendships ALTER COLUMN id SET DEFAULT nextval('public.chat_friendships_id_seq'::regclass);


--
-- Name: chat_messages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_messages ALTER COLUMN id SET DEFAULT nextval('public.chat_messages_id_seq'::regclass);


--
-- Name: chat_room_keys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_room_keys ALTER COLUMN id SET DEFAULT nextval('public.chat_room_keys_id_seq'::regclass);


--
-- Name: chat_rooms id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_rooms ALTER COLUMN id SET DEFAULT nextval('public.chat_rooms_id_seq1'::regclass);


--
-- Name: chat_users id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_users ALTER COLUMN id SET DEFAULT nextval('public.chat_users_id_seq'::regclass);


--
-- Name: reports id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reports ALTER COLUMN id SET DEFAULT nextval('public.reports_id_seq'::regclass);


--
-- Name: room_seen id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.room_seen ALTER COLUMN id SET DEFAULT nextval('public.room_seen_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Name: admin_audit admin_audit_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_audit
    ADD CONSTRAINT admin_audit_pkey PRIMARY KEY (id);


--
-- Name: admin_users admin_users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_users
    ADD CONSTRAINT admin_users_pkey PRIMARY KEY (user_id);


--
-- Name: chat_dm_delete_requests chat_dm_delete_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_dm_delete_requests
    ADD CONSTRAINT chat_dm_delete_requests_pkey PRIMARY KEY (thread_id, requester_id);


--
-- Name: chat_dm_delivery chat_dm_delivery_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_dm_delivery
    ADD CONSTRAINT chat_dm_delivery_pkey PRIMARY KEY (thread_id);


--
-- Name: chat_dm_key_archive chat_dm_key_archive_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_dm_key_archive
    ADD CONSTRAINT chat_dm_key_archive_pkey PRIMARY KEY (thread_id, user_id, key_id);


--
-- Name: chat_dm_members chat_dm_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_dm_members
    ADD CONSTRAINT chat_dm_members_pkey PRIMARY KEY (thread_id, user_id);


--
-- Name: chat_dm_messages chat_dm_messages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_dm_messages
    ADD CONSTRAINT chat_dm_messages_pkey PRIMARY KEY (id);


--
-- Name: chat_dm_pairs chat_dm_pairs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_dm_pairs
    ADD CONSTRAINT chat_dm_pairs_pkey PRIMARY KEY (user_low, user_high);


--
-- Name: chat_dm_pairs chat_dm_pairs_thread_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_dm_pairs
    ADD CONSTRAINT chat_dm_pairs_thread_id_key UNIQUE (thread_id);


--
-- Name: chat_dm_thread_keys chat_dm_thread_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_dm_thread_keys
    ADD CONSTRAINT chat_dm_thread_keys_pkey PRIMARY KEY (thread_id, user_id);


--
-- Name: chat_dm_threads chat_dm_threads_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_dm_threads
    ADD CONSTRAINT chat_dm_threads_pkey PRIMARY KEY (id);


--
-- Name: chat_dm_ud_nonces chat_dm_ud_nonces_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_dm_ud_nonces
    ADD CONSTRAINT chat_dm_ud_nonces_pkey PRIMARY KEY (thread_id, nonce);


--
-- Name: chat_feedback chat_feedback_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_feedback
    ADD CONSTRAINT chat_feedback_pkey PRIMARY KEY (id);


--
-- Name: chat_files chat_files_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_files
    ADD CONSTRAINT chat_files_pkey PRIMARY KEY (id);


--
-- Name: chat_files chat_files_token_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_files
    ADD CONSTRAINT chat_files_token_key UNIQUE (token);


--
-- Name: chat_friendships chat_friendships_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_friendships
    ADD CONSTRAINT chat_friendships_pkey PRIMARY KEY (id);


--
-- Name: chat_messages chat_messages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_messages
    ADD CONSTRAINT chat_messages_pkey PRIMARY KEY (id);


--
-- Name: chat_room_key_archive chat_room_key_archive_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_room_key_archive
    ADD CONSTRAINT chat_room_key_archive_pkey PRIMARY KEY (room_id, user_id, key_id);


--
-- Name: chat_room_keys chat_room_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_room_keys
    ADD CONSTRAINT chat_room_keys_pkey PRIMARY KEY (id);


--
-- Name: chat_room_keys chat_room_keys_room_id_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_room_keys
    ADD CONSTRAINT chat_room_keys_room_id_user_id_key UNIQUE (room_id, user_id);


--
-- Name: chat_room_members chat_room_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_room_members
    ADD CONSTRAINT chat_room_members_pkey PRIMARY KEY (room_id, user_id);


--
-- Name: chat_room_pins chat_room_pins_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_room_pins
    ADD CONSTRAINT chat_room_pins_pkey PRIMARY KEY (room_id);


--
-- Name: chat_rooms chat_rooms_owner_user_id_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_rooms
    ADD CONSTRAINT chat_rooms_owner_user_id_name_key UNIQUE (owner_user_id, name);


--
-- Name: chat_rooms chat_rooms_pkey1; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_rooms
    ADD CONSTRAINT chat_rooms_pkey1 PRIMARY KEY (id);


--
-- Name: chat_user_keys chat_user_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_user_keys
    ADD CONSTRAINT chat_user_keys_pkey PRIMARY KEY (user_id, alg, kid);


--
-- Name: chat_user_profiles chat_user_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_user_profiles
    ADD CONSTRAINT chat_user_profiles_pkey PRIMARY KEY (user_id);


--
-- Name: chat_users chat_users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_users
    ADD CONSTRAINT chat_users_pkey PRIMARY KEY (id);


--
-- Name: chat_users chat_users_username_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_users
    ADD CONSTRAINT chat_users_username_key UNIQUE (username);


--
-- Name: refresh_tokens refresh_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_pkey PRIMARY KEY (jti);


--
-- Name: reports reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_pkey PRIMARY KEY (id);


--
-- Name: room_seen room_seen_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.room_seen
    ADD CONSTRAINT room_seen_pkey PRIMARY KEY (id);


--
-- Name: room_seen room_seen_room_id_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.room_seen
    ADD CONSTRAINT room_seen_room_id_user_id_key UNIQUE (room_id, user_id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users users_username_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);


--
-- Name: chat_dm_messages_thread_ts_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_dm_messages_thread_ts_idx ON public.chat_dm_messages USING btree (thread_id, ts);


--
-- Name: chat_dm_threads_last_message_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_dm_threads_last_message_idx ON public.chat_dm_threads USING btree (last_message_at DESC);


--
-- Name: chat_feedback_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_feedback_created_at_idx ON public.chat_feedback USING btree (created_at DESC);


--
-- Name: chat_feedback_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_feedback_user_id_idx ON public.chat_feedback USING btree (user_id, created_at DESC);


--
-- Name: chat_files_expires_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_files_expires_at_idx ON public.chat_files USING btree (expires_at);


--
-- Name: chat_files_room_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_files_room_id_idx ON public.chat_files USING btree (room_id);


--
-- Name: chat_friendships_addressee_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_friendships_addressee_idx ON public.chat_friendships USING btree (addressee_id);


--
-- Name: chat_friendships_pair_uniq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX chat_friendships_pair_uniq ON public.chat_friendships USING btree (LEAST(requester_id, addressee_id), GREATEST(requester_id, addressee_id));


--
-- Name: chat_friendships_requester_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_friendships_requester_idx ON public.chat_friendships USING btree (requester_id);


--
-- Name: chat_friendships_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_friendships_status_idx ON public.chat_friendships USING btree (status);


--
-- Name: chat_room_pins_created_by_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_room_pins_created_by_idx ON public.chat_room_pins USING btree (created_by);


--
-- Name: chat_rooms_alias_uq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX chat_rooms_alias_uq ON public.chat_rooms USING btree (alias);


--
-- Name: idx_admin_audit_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_admin_audit_action ON public.admin_audit USING btree (action);


--
-- Name: idx_admin_audit_actor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_admin_audit_actor ON public.admin_audit USING btree (actor);


--
-- Name: idx_admin_audit_ts; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_admin_audit_ts ON public.admin_audit USING btree (ts DESC);


--
-- Name: idx_admin_users_role; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_admin_users_role ON public.admin_users USING btree (role);


--
-- Name: idx_chat_files_thread_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_files_thread_id ON public.chat_files USING btree (thread_id);


--
-- Name: idx_chat_messages_room_ts; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_messages_room_ts ON public.chat_messages USING btree (room, ts DESC);


--
-- Name: idx_chat_messages_roomid_ts; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_messages_roomid_ts ON public.chat_messages USING btree (room_id, ts DESC);


--
-- Name: idx_chat_room_members_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_room_members_user ON public.chat_room_members USING btree (user_id);


--
-- Name: idx_chat_user_profiles_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_user_profiles_updated_at ON public.chat_user_profiles USING btree (updated_at DESC);


--
-- Name: idx_dm_delete_requests_exp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dm_delete_requests_exp ON public.chat_dm_delete_requests USING btree (expires_at);


--
-- Name: idx_dm_key_archive_thread_user_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dm_key_archive_thread_user_created ON public.chat_dm_key_archive USING btree (thread_id, user_id, created_at DESC);


--
-- Name: idx_refresh_tokens_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_refresh_tokens_expires ON public.refresh_tokens USING btree (expires_at) WHERE (revoked_at IS NULL);


--
-- Name: idx_refresh_tokens_family; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_refresh_tokens_family ON public.refresh_tokens USING btree (family_id);


--
-- Name: idx_refresh_tokens_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_refresh_tokens_user ON public.refresh_tokens USING btree (user_id);


--
-- Name: idx_reports_no_dup; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_reports_no_dup ON public.reports USING btree (reporter_id, target_type, target_id) WHERE (status = ANY (ARRAY['new'::text, 'in_review'::text]));


--
-- Name: idx_reports_reporter; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reports_reporter ON public.reports USING btree (reporter_id, created_at DESC);


--
-- Name: idx_reports_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reports_status ON public.reports USING btree (status, created_at DESC);


--
-- Name: idx_reports_target; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reports_target ON public.reports USING btree (target_type, target_id);


--
-- Name: idx_room_key_archive_room_user_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_room_key_archive_room_user_created ON public.chat_room_key_archive USING btree (room_id, user_id, created_at DESC);


--
-- Name: idx_room_keys_room; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_room_keys_room ON public.chat_room_keys USING btree (room_id);


--
-- Name: idx_room_keys_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_room_keys_user ON public.chat_room_keys USING btree (user_id);


--
-- Name: idx_room_members_room_role; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_room_members_room_role ON public.chat_room_members USING btree (room_id, role);


--
-- Name: idx_room_members_room_user_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_room_members_room_user_status ON public.chat_room_members USING btree (room_id, user_id, status);


--
-- Name: ix_dm_ud_nonces_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_dm_ud_nonces_created_at ON public.chat_dm_ud_nonces USING btree (created_at);


--
-- Name: users_username_lower_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX users_username_lower_idx ON public.users USING btree (lower(username));


--
-- Name: ux_chat_user_keys_one_active_alg; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ux_chat_user_keys_one_active_alg ON public.chat_user_keys USING btree (user_id, alg) WHERE is_active;


--
-- Name: ux_room_one_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ux_room_one_owner ON public.chat_room_members USING btree (room_id) WHERE (role = 'owner'::text);


--
-- Name: ux_users_username_ci; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ux_users_username_ci ON public.users USING btree (lower(username));


--
-- Name: admin_audit admin_audit_actor_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_audit
    ADD CONSTRAINT admin_audit_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: admin_users admin_users_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_users
    ADD CONSTRAINT admin_users_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_dm_delivery chat_dm_delivery_thread_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_dm_delivery
    ADD CONSTRAINT chat_dm_delivery_thread_id_fkey FOREIGN KEY (thread_id) REFERENCES public.chat_dm_threads(id) ON DELETE CASCADE;


--
-- Name: chat_dm_members chat_dm_members_thread_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_dm_members
    ADD CONSTRAINT chat_dm_members_thread_id_fkey FOREIGN KEY (thread_id) REFERENCES public.chat_dm_threads(id) ON DELETE CASCADE;


--
-- Name: chat_dm_members chat_dm_members_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_dm_members
    ADD CONSTRAINT chat_dm_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_dm_messages chat_dm_messages_thread_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_dm_messages
    ADD CONSTRAINT chat_dm_messages_thread_id_fkey FOREIGN KEY (thread_id) REFERENCES public.chat_dm_threads(id) ON DELETE CASCADE;


--
-- Name: chat_dm_messages chat_dm_messages_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_dm_messages
    ADD CONSTRAINT chat_dm_messages_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE RESTRICT;


--
-- Name: chat_dm_pairs chat_dm_pairs_thread_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_dm_pairs
    ADD CONSTRAINT chat_dm_pairs_thread_id_fkey FOREIGN KEY (thread_id) REFERENCES public.chat_dm_threads(id) ON DELETE CASCADE;


--
-- Name: chat_dm_pairs chat_dm_pairs_user_high_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_dm_pairs
    ADD CONSTRAINT chat_dm_pairs_user_high_fkey FOREIGN KEY (user_high) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_dm_pairs chat_dm_pairs_user_low_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_dm_pairs
    ADD CONSTRAINT chat_dm_pairs_user_low_fkey FOREIGN KEY (user_low) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_dm_thread_keys chat_dm_thread_keys_thread_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_dm_thread_keys
    ADD CONSTRAINT chat_dm_thread_keys_thread_id_fkey FOREIGN KEY (thread_id) REFERENCES public.chat_dm_threads(id) ON DELETE CASCADE;


--
-- Name: chat_dm_thread_keys chat_dm_thread_keys_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_dm_thread_keys
    ADD CONSTRAINT chat_dm_thread_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_dm_ud_nonces chat_dm_ud_nonces_thread_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_dm_ud_nonces
    ADD CONSTRAINT chat_dm_ud_nonces_thread_id_fkey FOREIGN KEY (thread_id) REFERENCES public.chat_dm_threads(id) ON DELETE CASCADE;


--
-- Name: chat_files chat_files_room_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_files
    ADD CONSTRAINT chat_files_room_id_fkey FOREIGN KEY (room_id) REFERENCES public.chat_rooms(id) ON DELETE CASCADE;


--
-- Name: chat_files chat_files_uploader_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_files
    ADD CONSTRAINT chat_files_uploader_user_id_fkey FOREIGN KEY (uploader_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_friendships chat_friendships_addressee_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_friendships
    ADD CONSTRAINT chat_friendships_addressee_id_fkey FOREIGN KEY (addressee_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_friendships chat_friendships_requester_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_friendships
    ADD CONSTRAINT chat_friendships_requester_id_fkey FOREIGN KEY (requester_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_room_keys chat_room_keys_member_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_room_keys
    ADD CONSTRAINT chat_room_keys_member_fk FOREIGN KEY (room_id, user_id) REFERENCES public.chat_room_members(room_id, user_id) ON DELETE CASCADE;


--
-- Name: chat_room_keys chat_room_keys_room_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_room_keys
    ADD CONSTRAINT chat_room_keys_room_id_fkey FOREIGN KEY (room_id) REFERENCES public.chat_rooms(id) ON DELETE CASCADE;


--
-- Name: chat_room_keys chat_room_keys_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_room_keys
    ADD CONSTRAINT chat_room_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_room_members chat_room_members_invited_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_room_members
    ADD CONSTRAINT chat_room_members_invited_by_fkey FOREIGN KEY (invited_by) REFERENCES public.users(id);


--
-- Name: chat_room_members chat_room_members_room_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_room_members
    ADD CONSTRAINT chat_room_members_room_id_fkey FOREIGN KEY (room_id) REFERENCES public.chat_rooms(id) ON DELETE CASCADE;


--
-- Name: chat_room_members chat_room_members_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_room_members
    ADD CONSTRAINT chat_room_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_room_pins chat_room_pins_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_room_pins
    ADD CONSTRAINT chat_room_pins_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_room_pins chat_room_pins_room_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_room_pins
    ADD CONSTRAINT chat_room_pins_room_id_fkey FOREIGN KEY (room_id) REFERENCES public.chat_rooms(id) ON DELETE CASCADE;


--
-- Name: chat_rooms chat_rooms_owner_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_rooms
    ADD CONSTRAINT chat_rooms_owner_user_id_fkey FOREIGN KEY (owner_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_user_keys chat_user_keys_user_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_user_keys
    ADD CONSTRAINT chat_user_keys_user_fk FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_user_profiles chat_user_profiles_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_user_profiles
    ADD CONSTRAINT chat_user_profiles_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_messages fk_chat_messages_room; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_messages
    ADD CONSTRAINT fk_chat_messages_room FOREIGN KEY (room_id) REFERENCES public.chat_rooms(id) ON DELETE CASCADE;


--
-- Name: chat_messages fk_chat_messages_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_messages
    ADD CONSTRAINT fk_chat_messages_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: refresh_tokens refresh_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: reports reports_reporter_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_reporter_id_fkey FOREIGN KEY (reporter_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: reports reports_reviewer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_reviewer_id_fkey FOREIGN KEY (reviewer_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: room_seen room_seen_room_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.room_seen
    ADD CONSTRAINT room_seen_room_id_fkey FOREIGN KEY (room_id) REFERENCES public.chat_rooms(id) ON DELETE CASCADE;


--
-- Name: room_seen room_seen_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.room_seen
    ADD CONSTRAINT room_seen_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- End of schema
--
