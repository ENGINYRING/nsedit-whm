CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    emailaddress TEXT NOT NULL UNIQUE,
    cpanel_username TEXT UNIQUE, -- Added cpanel_username, make it UNIQUE if one cPanel user maps to one app user
    password TEXT NOT NULL,
    isadmin INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS zones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    zone TEXT NOT NULL UNIQUE,
    owner INTEGER NOT NULL,
    FOREIGN KEY(owner) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY,
    user TEXT NOT NULL,
    log TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Default admin user is now created in misc.inc.php if DB is new,
-- so no need for an INSERT statement here unless you want a different default.
-- The misc.inc.php logic will handle creating the admin with cpanel_username.
