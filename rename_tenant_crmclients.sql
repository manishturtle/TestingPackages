-- SQL script to rename the table and column in all tenant schemas

-- Function to execute SQL in all tenant schemas
CREATE OR REPLACE FUNCTION execute_in_all_tenant_schemas(query text) RETURNS void AS $$
DECLARE
    schema_name text;
BEGIN
    FOR schema_name IN 
        SELECT nspname FROM pg_namespace 
        WHERE nspname NOT IN ('public', 'information_schema', 'pg_catalog', 'pg_toast')
        AND nspname NOT LIKE 'pg_%'
    LOOP
        BEGIN
            EXECUTE format('SET search_path TO %I', schema_name);
            
            -- Check if the old table exists in this schema
            PERFORM 1 FROM information_schema.tables 
            WHERE table_schema = schema_name 
            AND table_name = 'ecomm_tenant_admin_crmclients';
            
            IF FOUND THEN
                -- Execute the provided query
                EXECUTE query;
                RAISE NOTICE 'Successfully executed in schema: %', schema_name;
            ELSE
                RAISE NOTICE 'Table does not exist in schema: %', schema_name;
            END IF;
            
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'Error in schema %: %', schema_name, SQLERRM;
        END;
    END LOOP;
    
    -- Reset search path
    SET search_path TO public;
END;
$$ LANGUAGE plpgsql;

-- First, rename the column in each schema
SELECT execute_in_all_tenant_schemas(
    'ALTER TABLE ecomm_tenant_admin_crmclients RENAME COLUMN contactperson_email TO contact_person_email;'
);

-- Then, rename the table in each schema
SELECT execute_in_all_tenant_schemas(
    'ALTER TABLE ecomm_tenant_admin_crmclients RENAME TO ecomm_tenant_admins_crmclients;'
);

-- Drop the function when done
DROP FUNCTION execute_in_all_tenant_schemas;

-- Confirm the changes
SET search_path TO qa;
SELECT * FROM information_schema.tables WHERE table_name = 'ecomm_tenant_admins_crmclients';
SELECT column_name FROM information_schema.columns WHERE table_name = 'ecomm_tenant_admins_crmclients';
SET search_path TO public;
