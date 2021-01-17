ALTER TABLE public.oauth_apps ADD client_type_public boolean NOT NULL DEFAULT False;
ALTER TABLE public.client_auths ADD code_challenge varchar(128) NULL;
ALTER TABLE public.client_auths ADD code_challenge_method varchar(32) NULL;
