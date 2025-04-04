-- SQL script to update the company-client relationship in the 'qa' schema

-- Switch to the 'qa' schema
SET search_path TO qa;

-- First make sure the client_id column exists in the company table
DO $$
BEGIN
    -- Check if client_id column exists
    IF NOT EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_schema = 'qa' 
        AND table_name = 'ecomm_tenant_admins_company' 
        AND column_name = 'client_id'
    ) THEN
        -- Add the client_id column if it doesn't exist
        ALTER TABLE ecomm_tenant_admins_company ADD COLUMN client_id INTEGER;
    END IF;
END $$;

-- Add foreign key constraint if it doesn't exist
DO $$
BEGIN
    -- Check if the foreign key constraint already exists
    IF NOT EXISTS (
        SELECT 1 
        FROM information_schema.table_constraints 
        WHERE constraint_schema = 'qa' 
        AND table_name = 'ecomm_tenant_admins_company' 
        AND constraint_name = 'ecomm_tenant_admins_company_client_id_fk'
    ) THEN
        -- Add the foreign key constraint
        ALTER TABLE ecomm_tenant_admins_company 
        ADD CONSTRAINT ecomm_tenant_admins_company_client_id_fk 
        FOREIGN KEY (client_id) 
        REFERENCES ecomm_tenant_admin_crmclients(client_id)
        ON DELETE SET NULL;
    END IF;
END $$;

-- Reset search path
SET search_path TO public;
