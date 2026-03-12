-- Migrate static_ips: drop integer id, make ip_address the primary key
CREATE TABLE IF NOT EXISTS static_ips_new (
    ip_address TEXT NOT NULL PRIMARY KEY,
    subnet_id INTEGER NOT NULL,
    mac_address TEXT NOT NULL,
    hostname TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    UNIQUE(mac_address),
    FOREIGN KEY (subnet_id) REFERENCES subnets(id) ON DELETE CASCADE
);

INSERT INTO static_ips_new (ip_address, subnet_id, mac_address, hostname, enabled, created_at)
SELECT ip_address, subnet_id, mac_address, hostname, enabled, created_at FROM static_ips;

DROP TABLE static_ips;

ALTER TABLE static_ips_new RENAME TO static_ips;

-- Recreate indexes
CREATE INDEX IF NOT EXISTS idx_static_ips_subnet ON static_ips(subnet_id);
CREATE INDEX IF NOT EXISTS idx_static_ips_mac ON static_ips(mac_address);
