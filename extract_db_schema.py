#!/usr/bin/env python3
"""
Extract complete PostgreSQL database schema with all details
"""
import psycopg2
from psycopg2.extras import RealDictCursor
import json
from src.config.database import get_secure_database_url

DATABASE_URL = get_secure_database_url()

def get_complete_schema():
    """Extract complete database schema with all details"""
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    schema = {
        "tables": {},
        "indexes": {},
        "constraints": {},
        "sequences": {},
        "views": {},
        "functions": {},
        "triggers": {}
    }
    
    # Get all tables
    cur.execute("""
        SELECT 
            table_name,
            table_type
        FROM information_schema.tables
        WHERE table_schema = 'public'
        ORDER BY table_name;
    """)
    tables = cur.fetchall()
    
    for table in tables:
        table_name = table['table_name']
        
        # Get columns for each table
        cur.execute("""
            SELECT 
                column_name,
                data_type,
                character_maximum_length,
                column_default,
                is_nullable,
                numeric_precision,
                numeric_scale,
                datetime_precision,
                udt_name
            FROM information_schema.columns
            WHERE table_schema = 'public' 
            AND table_name = %s
            ORDER BY ordinal_position;
        """, (table_name,))
        columns = cur.fetchall()
        
        # Get primary key
        cur.execute("""
            SELECT 
                kcu.column_name,
                tc.constraint_name
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
                ON tc.constraint_name = kcu.constraint_name
                AND tc.table_schema = kcu.table_schema
            WHERE tc.constraint_type = 'PRIMARY KEY'
            AND tc.table_schema = 'public'
            AND tc.table_name = %s;
        """, (table_name,))
        primary_keys = cur.fetchall()
        
        # Get foreign keys
        cur.execute("""
            SELECT
                kcu.column_name,
                ccu.table_name AS foreign_table_name,
                ccu.column_name AS foreign_column_name,
                tc.constraint_name,
                rc.update_rule,
                rc.delete_rule
            FROM information_schema.table_constraints AS tc
            JOIN information_schema.key_column_usage AS kcu
                ON tc.constraint_name = kcu.constraint_name
                AND tc.table_schema = kcu.table_schema
            JOIN information_schema.constraint_column_usage AS ccu
                ON ccu.constraint_name = tc.constraint_name
                AND ccu.table_schema = tc.table_schema
            JOIN information_schema.referential_constraints AS rc
                ON tc.constraint_name = rc.constraint_name
            WHERE tc.constraint_type = 'FOREIGN KEY'
            AND tc.table_schema = 'public'
            AND tc.table_name = %s;
        """, (table_name,))
        foreign_keys = cur.fetchall()
        
        # Get unique constraints
        cur.execute("""
            SELECT 
                kcu.column_name,
                tc.constraint_name
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
                ON tc.constraint_name = kcu.constraint_name
                AND tc.table_schema = kcu.table_schema
            WHERE tc.constraint_type = 'UNIQUE'
            AND tc.table_schema = 'public'
            AND tc.table_name = %s;
        """, (table_name,))
        unique_constraints = cur.fetchall()
        
        # Get check constraints
        cur.execute("""
            SELECT 
                cc.constraint_name,
                cc.check_clause
            FROM information_schema.check_constraints cc
            JOIN information_schema.table_constraints tc
                ON cc.constraint_name = tc.constraint_name
            WHERE tc.table_schema = 'public'
            AND tc.table_name = %s;
        """, (table_name,))
        check_constraints = cur.fetchall()
        
        # Get indexes
        cur.execute("""
            SELECT
                indexname,
                indexdef
            FROM pg_indexes
            WHERE schemaname = 'public'
            AND tablename = %s;
        """, (table_name,))
        indexes = cur.fetchall()
        
        # Get table size
        cur.execute("""
            SELECT 
                pg_size_pretty(pg_total_relation_size(%s)) as total_size,
                pg_size_pretty(pg_relation_size(%s)) as table_size,
                pg_size_pretty(pg_total_relation_size(%s) - pg_relation_size(%s)) as indexes_size
        """, (table_name, table_name, table_name, table_name))
        size_info = cur.fetchone()
        
        # Get row count
        try:
            cur.execute(f"SELECT COUNT(*) as row_count FROM {table_name}")
            row_count = cur.fetchone()['row_count']
        except:
            row_count = 0
        
        schema["tables"][table_name] = {
            "type": table['table_type'],
            "columns": [dict(col) for col in columns],
            "primary_keys": [dict(pk) for pk in primary_keys],
            "foreign_keys": [dict(fk) for fk in foreign_keys],
            "unique_constraints": [dict(uc) for uc in unique_constraints],
            "check_constraints": [dict(cc) for cc in check_constraints],
            "indexes": [dict(idx) for idx in indexes],
            "size_info": dict(size_info) if size_info else {},
            "row_count": row_count
        }
    
    # Get all sequences
    cur.execute("""
        SELECT 
            sequence_name,
            data_type,
            start_value,
            minimum_value,
            maximum_value,
            increment,
            cycle_option
        FROM information_schema.sequences
        WHERE sequence_schema = 'public';
    """)
    sequences = cur.fetchall()
    for seq in sequences:
        schema["sequences"][seq['sequence_name']] = dict(seq)
    
    # Get all views
    cur.execute("""
        SELECT 
            table_name as view_name,
            view_definition
        FROM information_schema.views
        WHERE table_schema = 'public';
    """)
    views = cur.fetchall()
    for view in views:
        schema["views"][view['view_name']] = dict(view)
    
    # Get all functions
    cur.execute("""
        SELECT 
            routine_name,
            routine_type,
            data_type as return_type,
            routine_definition
        FROM information_schema.routines
        WHERE routine_schema = 'public';
    """)
    functions = cur.fetchall()
    for func in functions:
        schema["functions"][func['routine_name']] = dict(func)
    
    # Get all triggers
    cur.execute("""
        SELECT 
            trigger_name,
            event_manipulation,
            event_object_table,
            action_statement,
            action_timing
        FROM information_schema.triggers
        WHERE trigger_schema = 'public';
    """)
    triggers = cur.fetchall()
    for trigger in triggers:
        schema["triggers"][trigger['trigger_name']] = dict(trigger)
    
    cur.close()
    conn.close()
    
    return schema

def format_schema_markdown(schema):
    """Format schema as detailed markdown"""
    md = ["# PostgreSQL Database Schema - AutoVulRepair\n"]
    md.append(f"**Total Tables:** {len(schema['tables'])}\n")
    md.append(f"**Total Sequences:** {len(schema['sequences'])}\n")
    md.append(f"**Total Views:** {len(schema['views'])}\n")
    md.append(f"**Total Functions:** {len(schema['functions'])}\n")
    md.append(f"**Total Triggers:** {len(schema['triggers'])}\n\n")
    
    md.append("---\n\n")
    
    # Tables
    md.append("## Tables\n\n")
    for table_name, table_info in sorted(schema['tables'].items()):
        md.append(f"### {table_name}\n\n")
        md.append(f"**Type:** {table_info['type']}\n")
        md.append(f"**Row Count:** {table_info['row_count']:,}\n")
        if table_info['size_info']:
            md.append(f"**Total Size:** {table_info['size_info'].get('total_size', 'N/A')}\n")
            md.append(f"**Table Size:** {table_info['size_info'].get('table_size', 'N/A')}\n")
            md.append(f"**Indexes Size:** {table_info['size_info'].get('indexes_size', 'N/A')}\n")
        md.append("\n")
        
        # Columns
        md.append("#### Columns\n\n")
        md.append("| Column | Type | Nullable | Default | Max Length | Precision | Scale |\n")
        md.append("|--------|------|----------|---------|------------|-----------|-------|\n")
        for col in table_info['columns']:
            col_type = col['data_type']
            if col['character_maximum_length']:
                col_type += f"({col['character_maximum_length']})"
            elif col['numeric_precision']:
                if col['numeric_scale']:
                    col_type += f"({col['numeric_precision']},{col['numeric_scale']})"
                else:
                    col_type += f"({col['numeric_precision']})"
            
            md.append(f"| {col['column_name']} | {col_type} | {col['is_nullable']} | "
                     f"{col['column_default'] or '-'} | {col['character_maximum_length'] or '-'} | "
                     f"{col['numeric_precision'] or '-'} | {col['numeric_scale'] or '-'} |\n")
        md.append("\n")
        
        # Primary Keys
        if table_info['primary_keys']:
            md.append("#### Primary Keys\n\n")
            for pk in table_info['primary_keys']:
                md.append(f"- **{pk['column_name']}** (Constraint: `{pk['constraint_name']}`)\n")
            md.append("\n")
        
        # Foreign Keys
        if table_info['foreign_keys']:
            md.append("#### Foreign Keys\n\n")
            md.append("| Column | References | Constraint | On Update | On Delete |\n")
            md.append("|--------|------------|------------|-----------|----------|\n")
            for fk in table_info['foreign_keys']:
                md.append(f"| {fk['column_name']} | {fk['foreign_table_name']}.{fk['foreign_column_name']} | "
                         f"{fk['constraint_name']} | {fk['update_rule']} | {fk['delete_rule']} |\n")
            md.append("\n")
        
        # Unique Constraints
        if table_info['unique_constraints']:
            md.append("#### Unique Constraints\n\n")
            for uc in table_info['unique_constraints']:
                md.append(f"- **{uc['column_name']}** (Constraint: `{uc['constraint_name']}`)\n")
            md.append("\n")
        
        # Check Constraints
        if table_info['check_constraints']:
            md.append("#### Check Constraints\n\n")
            for cc in table_info['check_constraints']:
                md.append(f"- **{cc['constraint_name']}**: `{cc['check_clause']}`\n")
            md.append("\n")
        
        # Indexes
        if table_info['indexes']:
            md.append("#### Indexes\n\n")
            for idx in table_info['indexes']:
                md.append(f"**{idx['indexname']}**\n```sql\n{idx['indexdef']}\n```\n\n")
        
        md.append("---\n\n")
    
    # Sequences
    if schema['sequences']:
        md.append("## Sequences\n\n")
        for seq_name, seq_info in sorted(schema['sequences'].items()):
            md.append(f"### {seq_name}\n\n")
            md.append(f"- **Data Type:** {seq_info['data_type']}\n")
            md.append(f"- **Start Value:** {seq_info['start_value']}\n")
            md.append(f"- **Min Value:** {seq_info['minimum_value']}\n")
            md.append(f"- **Max Value:** {seq_info['maximum_value']}\n")
            md.append(f"- **Increment:** {seq_info['increment']}\n")
            md.append(f"- **Cycle:** {seq_info['cycle_option']}\n\n")
    
    # Views
    if schema['views']:
        md.append("## Views\n\n")
        for view_name, view_info in sorted(schema['views'].items()):
            md.append(f"### {view_name}\n\n")
            md.append(f"```sql\n{view_info['view_definition']}\n```\n\n")
    
    # Functions
    if schema['functions']:
        md.append("## Functions\n\n")
        for func_name, func_info in sorted(schema['functions'].items()):
            md.append(f"### {func_name}\n\n")
            md.append(f"- **Type:** {func_info['routine_type']}\n")
            md.append(f"- **Return Type:** {func_info['return_type']}\n")
            if func_info['routine_definition']:
                md.append(f"\n```sql\n{func_info['routine_definition']}\n```\n\n")
    
    # Triggers
    if schema['triggers']:
        md.append("## Triggers\n\n")
        for trigger_name, trigger_info in sorted(schema['triggers'].items()):
            md.append(f"### {trigger_name}\n\n")
            md.append(f"- **Event:** {trigger_info['event_manipulation']}\n")
            md.append(f"- **Table:** {trigger_info['event_object_table']}\n")
            md.append(f"- **Timing:** {trigger_info['action_timing']}\n")
            md.append(f"- **Action:** `{trigger_info['action_statement']}`\n\n")
    
    return ''.join(md)

if __name__ == "__main__":
    print("Extracting PostgreSQL database schema...")
    
    try:
        schema = get_complete_schema()
        
        # Save as JSON
        with open('DATABASE_SCHEMA.json', 'w') as f:
            json.dump(schema, f, indent=2, default=str)
        print("✓ Saved schema to DATABASE_SCHEMA.json")
        
        # Save as Markdown
        markdown = format_schema_markdown(schema)
        with open('DATABASE_SCHEMA.md', 'w') as f:
            f.write(markdown)
        print("✓ Saved schema to DATABASE_SCHEMA.md")
        
        print(f"\nSchema Summary:")
        print(f"  Tables: {len(schema['tables'])}")
        print(f"  Sequences: {len(schema['sequences'])}")
        print(f"  Views: {len(schema['views'])}")
        print(f"  Functions: {len(schema['functions'])}")
        print(f"  Triggers: {len(schema['triggers'])}")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
