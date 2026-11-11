-- ═══════════════════════════════════════════════════════════════════════════
--  ETS — the sites that are reached only through the office server
--
--  The owner's ask: WHMCS (portal.99rdp.com/admin) must open only while the
--  person is signed in to Amaze Connect, and must reach the site FROM this
--  server's IP. The web-protection (DDoS-Guard) rules then allow /admin/* for
--  this server's IP alone, so the same URL from anywhere else is refused.
--
--  This row is the list of hostnames the app sends through the server. A
--  super admin edits it in Settings. It is a JSON array of hostnames; an entry
--  starting with "*." also covers every subdomain.
--
--  Seeded with the one the owner named, so the feature works the day it is
--  deployed. Idempotent: an edited list is never overwritten.
-- ═══════════════════════════════════════════════════════════════════════════

BEGIN;

INSERT INTO app_settings (key, value) VALUES
    ('tunnel_domains', '["portal.99rdp.com"]')
ON CONFLICT (key) DO NOTHING;

COMMIT;
