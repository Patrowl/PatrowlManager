-- Create user if not exists
DO $$
BEGIN
   IF NOT EXISTS (
      SELECT FROM pg_catalog.pg_roles  -- SELECT list can be empty for this
      WHERE  rolname = 'PATROWL_DB_USER') THEN

      CREATE USER 'PATROWL_DB_USER' WITH PASSWORD 'PATROWL_DB_PASSWD_TO_CHANGE';
   END IF;
END
$$;


SELECT 'CREATE DATABASE patrowl_db WITH OWNER "PATROWL_DB_USER"'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'patrowl_db')\gexec

ALTER ROLE "PATROWL_DB_USER" SET client_encoding TO 'utf8';
ALTER ROLE "PATROWL_DB_USER" SET default_transaction_isolation TO 'read committed';
GRANT ALL PRIVILEGES ON DATABASE "patrowl_db" TO "PATROWL_DB_USER";
