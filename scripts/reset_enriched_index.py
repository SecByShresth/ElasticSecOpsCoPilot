"""
Script to delete and recreate the security-alerts-enriched index
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ingestion.elastic_client import ElasticClient

def main():
    print("Connecting to Elasticsearch...")
    client = ElasticClient()
    
    index_name = "security-alerts-enriched"
    
    try:
        # Check if index exists
        if client.client.indices.exists(index=index_name):
            print(f"\n⚠️  Index '{index_name}' exists with corrupted field mappings")
            print("Deleting old index...")
            
            client.client.indices.delete(index=index_name)
            print(f"✅ Deleted index: {index_name}")
        else:
            print(f"ℹ️  Index '{index_name}' does not exist")
        
        print("\n✅ Ready to run enrichment service!")
        print("The index will be auto-created on first document write.\n")
        
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    main()
