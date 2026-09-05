# CogNexus self-serve stack — rendered by `artzain local up` (WS-B).
#
# Do not edit by hand: `artzain local upgrade` rewrites this file with the
# next release's digests. Durable configuration lives in the .env beside it,
# which the installer generates once and never overwrites.
#
# Images are pinned BY DIGEST from the stable-channel manifest — the public
# registry has no tag immutability, so the digest is the only anchor, and it
# is the same digest the release's cosign signature covers.

services:

  postgres:
    # Digest-pinned like everything else in this file — "never a bare tag"
    # must hold for the container holding the system of record too. Bump the
    # digest deliberately with SDK releases (multi-arch index digest of
    # postgres:16-alpine at pin time).
    image: postgres:16-alpine@sha256:075f7ba66bc9b3ce7d6b8b635208ff61cd7cf1a67d71ec530eec5d7ae0cbe571
    container_name: cognexus-local-postgres
    environment:
      POSTGRES_DB: cognexus
      POSTGRES_USER: cognexus
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - cognexus-pg-data:/var/lib/postgresql/data
    networks:
      - cognexus-local
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U cognexus"]
      interval: 5s
      timeout: 5s
      retries: 10

  analyzer:
    image: __CORE_IMAGE__
    container_name: cognexus-local-analyzer
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      - COGNEXUS_DEPLOYMENT_PROFILE=core
      - DATABASE_URL=postgresql://cognexus:${POSTGRES_PASSWORD}@postgres:5432/cognexus
      - JWT_SECRET_KEY=${JWT_SECRET_KEY}
      - COGNEXUS_API_KEY_PEPPER=${COGNEXUS_API_KEY_PEPPER}
      # Real generated secrets, so production's fail-closed secret checks pass.
      - APP_ENV=production
      - COGNEXUS_ENV=production
      - COGNEXUS_AUDIT_SEALER=dual
      - COGNEXUS_AUDIT_RETENTION_YEARS=7
      - COGNEXUS_AUDIT_KEY_DIR=/var/cognexus/audit-keys
      # First-run bootstrap (manual §8.1): /welcome?token=<this> creates the
      # first verified platform admin — no email infrastructure needed.
      - COGNEXUS_BOOTSTRAP_TOKEN=${COGNEXUS_BOOTSTRAP_TOKEN}
      # Observe posture for a fresh evaluation install — the operator
      # checklist walks through flipping enforcement deliberately.
      - COGNEXUS_IDENTITY_BINDING=observe
      - COGNEXUS_CAPABILITY_ENFORCEMENT=observe
      - COGNEXUS_UNREGISTERED_AGENTS=observe
      - COGNEXUS_PRODUCT_ENFORCEMENT=observe
      - COGNEXUS_CONTEXT_SCREENING=observe
      - COGNEXUS_CONTEXT_HISTORY=1
      - COGNEXUS_LIFECYCLE_GATE=observe
      - COGNEXUS_RECONCILE_ENFORCEMENT=observe
      - COGNEXUS_KILL_SWITCH_RBAC=1
      # The core image has no local LLM; keep the LLM-dependent scouts quiet
      # rather than surfacing permanent "degraded" noise on the status pill.
      - COGNEXUS_REGISTRY_SCOUT_DISABLED=1
      - COGNEXUS_GOVERNANCE_ANALYST_DISABLED=1
    volumes:
      - cognexus-audit-keys:/var/cognexus/audit-keys
    networks:
      - cognexus-local
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 10s
      timeout: 5s
      start_period: 90s
      retries: 12

  # The local dashboard is the point of the install — never behind a profile.
  frontend:
    image: __FRONTEND_IMAGE__
    container_name: cognexus-local-frontend
    ports:
      - "${COGNEXUS_UI_PORT}:80"
    depends_on:
      analyzer:
        condition: service_healthy
    networks:
      - cognexus-local
    restart: unless-stopped

volumes:
  # pg-data is the system of record; audit-keys holds the Ed25519 signing
  # keys, which are UNRECOVERABLE if lost (manual §2.7). `artzain local down`
  # keeps both; only `down --purge` destroys them, after an explicit confirm.
  cognexus-pg-data:
  cognexus-audit-keys:

networks:
  cognexus-local:
    driver: bridge
