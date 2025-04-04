-- SQL script to create the ecomm_tenant_admins_crmclients table in the 'qa' schema
-- and insert an initial value

-- Switch to the 'qa' schema
SET search_path TO qa;

-- Create the table if it doesn't exist
CREATE TABLE IF NOT EXISTS ecomm_tenant_admins_crmclients (
    client_id INTEGER PRIMARY KEY,
    client_name VARCHAR(255) NOT NULL,
    contact_person_email VARCHAR(255) NOT NULL,
    created_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by VARCHAR(255) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Insert the initial value
INSERT INTO ecomm_tenant_admins_crmclients (
    client_id, 
    client_name, 
    contact_person_email, 
    created_by, 
    created_at, 
    updated_by, 
    updated_at
) VALUES (
    2, 
    'QuickAssist Online', 
    'ankit@quickassist.co.in', 
    'ankit@turtlesoftware.co', 
    NOW(), 
    'ankit@turtlesoftware.co', 
    NOW()
) ON CONFLICT (client_id) DO NOTHING;

-- Reset search path
SET search_path TO public;
