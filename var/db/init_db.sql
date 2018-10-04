ALTER ROLE "PATROWL_DB_USER" SET client_encoding TO 'utf8';
ALTER ROLE "PATROWL_DB_USER" SET default_transaction_isolation TO 'read committed';
ALTER ROLE "PATROWL_DB_USER" SET timezone TO 'UTC';
GRANT ALL PRIVILEGES ON DATABASE "patrowl_db" TO "PATROWL_DB_USER";
