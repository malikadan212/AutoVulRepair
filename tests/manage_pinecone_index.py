"""
Pinecone Index Management Utility

Usage:
    # List all indexes
    python manage_pinecone_index.py --api-key YOUR_API_KEY --action list
    
    # Get index stats
    python manage_pinecone_index.py --api-key YOUR_API_KEY --action stats --index-name cve-vectors
    
    # Delete an index
    python manage_pinecone_index.py --api-key YOUR_API_KEY --action delete --index-name cve-test
"""

import argparse
from pinecone import Pinecone
import json


def list_indexes(pc: Pinecone):
    """List all indexes in the account"""
    indexes = pc.list_indexes()
    
    if not indexes:
        print("No indexes found in your account.")
        return
    
    print(f"\nFound {len(indexes)} index(es):\n")
    print(f"{'Name':<20} {'Dimension':<12} {'Metric':<10} {'Status':<10}")
    print("-" * 60)
    
    for idx in indexes:
        print(f"{idx.name:<20} {idx.dimension:<12} {idx.metric:<10} {idx.status['state']:<10}")


def get_stats(pc: Pinecone, index_name: str):
    """Get detailed statistics for an index"""
    try:
        # Get index description
        index_info = pc.describe_index(index_name)
        
        print(f"\nIndex: {index_name}")
        print("=" * 60)
        print(f"Dimension: {index_info.dimension}")
        print(f"Metric: {index_info.metric}")
        print(f"Status: {index_info.status['state']}")
        print(f"Host: {index_info.host}")
        
        # Get index stats
        index = pc.Index(index_name)
        stats = index.describe_index_stats()
        
        print(f"\nVector Statistics:")
        print("-" * 60)
        print(f"Total vectors: {stats['total_vector_count']:,}")
        print(f"Dimension: {stats['dimension']}")
        
        if 'namespaces' in stats and stats['namespaces']:
            print(f"\nNamespaces:")
            for ns_name, ns_stats in stats['namespaces'].items():
                print(f"  {ns_name}: {ns_stats['vector_count']:,} vectors")
        
        # Sample a few vectors
        print(f"\nSample vectors (first 5):")
        print("-" * 60)
        
        sample = index.query(
            vector=[0.0] * index_info.dimension,
            top_k=5,
            include_metadata=True
        )
        
        for i, match in enumerate(sample['matches'], 1):
            print(f"\n{i}. ID: {match['id']}")
            if 'metadata' in match:
                print(f"   Metadata: {json.dumps(match['metadata'], indent=6)}")
        
    except Exception as e:
        print(f"Error getting stats: {e}")


def delete_index(pc: Pinecone, index_name: str, confirm: bool = False):
    """Delete an index"""
    if not confirm:
        response = input(f"Are you sure you want to delete index '{index_name}'? (yes/no): ")
        if response.lower() != 'yes':
            print("Deletion cancelled.")
            return
    
    try:
        pc.delete_index(index_name)
        print(f"✓ Index '{index_name}' deleted successfully")
    except Exception as e:
        print(f"Error deleting index: {e}")


def fetch_vectors(pc: Pinecone, index_name: str, vector_ids: list):
    """Fetch specific vectors by ID"""
    try:
        index = pc.Index(index_name)
        
        print(f"\nFetching {len(vector_ids)} vector(s)...")
        result = index.fetch(ids=vector_ids)
        
        print(f"\nFound {len(result['vectors'])} vector(s):\n")
        
        for vec_id, vec_data in result['vectors'].items():
            print(f"ID: {vec_id}")
            print(f"Metadata: {json.dumps(vec_data.get('metadata', {}), indent=2)}")
            print(f"Vector dimensions: {len(vec_data['values'])}")
            print("-" * 60)
            
    except Exception as e:
        print(f"Error fetching vectors: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='Manage Pinecone indexes',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--api-key', required=True, help='Pinecone API key')
    parser.add_argument('--action', required=True, 
                       choices=['list', 'stats', 'delete', 'fetch'],
                       help='Action to perform')
    parser.add_argument('--index-name', help='Index name (required for stats, delete, fetch)')
    parser.add_argument('--vector-ids', nargs='+', help='Vector IDs to fetch (for fetch action)')
    parser.add_argument('--confirm', action='store_true', help='Skip confirmation for delete')
    
    args = parser.parse_args()
    
    # Initialize Pinecone
    pc = Pinecone(api_key=args.api_key)
    
    # Execute action
    if args.action == 'list':
        list_indexes(pc)
    
    elif args.action == 'stats':
        if not args.index_name:
            print("Error: --index-name required for stats action")
            return
        get_stats(pc, args.index_name)
    
    elif args.action == 'delete':
        if not args.index_name:
            print("Error: --index-name required for delete action")
            return
        delete_index(pc, args.index_name, args.confirm)
    
    elif args.action == 'fetch':
        if not args.index_name:
            print("Error: --index-name required for fetch action")
            return
        if not args.vector_ids:
            print("Error: --vector-ids required for fetch action")
            return
        fetch_vectors(pc, args.index_name, args.vector_ids)


if __name__ == '__main__':
    main()
