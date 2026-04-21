// Rootstock Neo4j Schema Initialization
// Run via: python3 graph/setup.py
// Safe to run multiple times (all statements are idempotent).

// ── Unique Constraints ─────────────────────────────────────────────────────

CREATE CONSTRAINT application_bundle_id IF NOT EXISTS
FOR (a:Application) REQUIRE a.bundle_id IS UNIQUE;

CREATE CONSTRAINT tcc_permission_service IF NOT EXISTS
FOR (t:TCC_Permission) REQUIRE t.service IS UNIQUE;

CREATE CONSTRAINT entitlement_name IF NOT EXISTS
FOR (e:Entitlement) REQUIRE e.name IS UNIQUE;

CREATE CONSTRAINT xpc_service_label IF NOT EXISTS
FOR (x:XPC_Service) REQUIRE x.label IS UNIQUE;

CREATE CONSTRAINT user_name IF NOT EXISTS
FOR (u:User) REQUIRE u.name IS UNIQUE;

CREATE CONSTRAINT launch_item_label IF NOT EXISTS
FOR (l:LaunchItem) REQUIRE l.label IS UNIQUE;

// ── Indexes ────────────────────────────────────────────────────────────────

CREATE INDEX application_hardened_runtime IF NOT EXISTS
FOR (a:Application) ON (a.hardened_runtime);

CREATE INDEX application_library_validation IF NOT EXISTS
FOR (a:Application) ON (a.library_validation);

CREATE INDEX application_is_electron IF NOT EXISTS
FOR (a:Application) ON (a.is_electron);

CREATE INDEX application_is_system IF NOT EXISTS
FOR (a:Application) ON (a.is_system);

CREATE INDEX entitlement_is_private IF NOT EXISTS
FOR (e:Entitlement) ON (e.is_private);

CREATE INDEX entitlement_category IF NOT EXISTS
FOR (e:Entitlement) ON (e.category);
