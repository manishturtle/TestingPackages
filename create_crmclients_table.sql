-- SQL script to create the ecomm_superadmin_crmclients table

CREATE TABLE IF NOT EXISTS ecomm_superadmin_crmclients (
    id SERIAL PRIMARY KEY,
    client_name VARCHAR(255) NOT NULL,
    contact_person_email VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Add an index on client_name for faster lookups
CREATE INDEX IF NOT EXISTS idx_crmclients_client_name ON ecomm_superadmin_crmclients(client_name);

-- Add an index on contact_person_email for faster lookups
CREATE INDEX IF NOT EXISTS idx_crmclients_contact_email ON ecomm_superadmin_crmclients(contact_person_email);
