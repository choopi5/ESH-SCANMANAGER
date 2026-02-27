"""
API sender module for sending API endpoint data to API endpoints.
"""
from .base_sender import *

def send_apis_to_api(project_id, file_path='api.txt', chunk_size=250):
    # Get absolute path if relative path is provided
    abs_file_path = os.path.abspath(file_path)
    server_url = API_BASE_URL
    
    print(f"\n{'='*80}")
    print("SENDING APIS REQUEST (CHUNKED)")
    print(f"{'='*80}")
    
    # Read APIs from file
    try:
        with open(abs_file_path, 'r') as file:
            # Read lines and strip whitespace
            apis = [line.strip() for line in file.readlines()]
            # Remove any empty lines
            apis = [api for api in apis if api]
    except Exception as e:
        print(f"Error reading file {abs_file_path}: {e}")
        return False
    
    if not apis:
        print("No APIs found in file")
        return False
    
    # Prepare API request URL
    url = server_url + "api_endpoints.php"
    headers = get_api_headers()
    
    # Split APIs into chunks
    total_apis = len(apis)
    total_chunks = (total_apis + chunk_size - 1) // chunk_size  # Ceiling division
    
    print(f"Total APIs to send: {total_apis}")
    print(f"Chunk size: {chunk_size}")
    print(f"Total chunks: {total_chunks}")
    print(f"{'='*80}\n")
    
    successful_chunks = 0
    failed_chunks = 0
    
    # Process each chunk
    for chunk_index in range(total_chunks):
        start_idx = chunk_index * chunk_size
        end_idx = min(start_idx + chunk_size, total_apis)
        chunk_apis = apis[start_idx:end_idx]
        
        print(f"\n📦 Processing chunk {chunk_index + 1}/{total_chunks}")
        print(f"   APIs {start_idx + 1}-{end_idx} of {total_apis}")
        
        # Prepare batch payload for this chunk
        api_list = []
        for api in chunk_apis:
            api_list.append({
                "api": api,
                "organization_id": project_id,
                "status": "active",
                "notes": f"Added via API - Project ID: {project_id}"
            })
        
        payload = {
            "apis": api_list
        }
        
        # Print request details for this chunk
        print(f"\nREQUEST DETAILS (Chunk {chunk_index + 1}):")
        print(f"URL: {url}")
        print(f"APIs in this chunk: {len(api_list)}")
        print(f"{'='*40}")

        # Send request for this chunk
        try:
            response = send_request_with_retry(url, payload, headers)
            
            # Print response details
            print(f"\nRESPONSE DETAILS (Chunk {chunk_index + 1}):")
            print(f"Status Code: {response.status_code}")
            
            if response.status_code in [200, 201]:
                print(f"✅ Successfully sent chunk {chunk_index + 1} ({len(api_list)} APIs)")
                successful_chunks += 1
            else:
                print(f"❌ Failed to send chunk {chunk_index + 1}. Status code: {response.status_code}")
                print(f"Response Body: {response.text}")
                failed_chunks += 1
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Request Error in chunk {chunk_index + 1}: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Error Response Status: {e.response.status_code}")
                print(f"Error Response Content: {e.response.text}")
            failed_chunks += 1
        except Exception as e:
            print(f"❌ Unexpected error in chunk {chunk_index + 1}: {str(e)}")
            failed_chunks += 1
        
        print(f"{'='*40}\n")
    
    # Print final summary
    print(f"\n{'='*80}")
    print("CHUNKED API SENDING SUMMARY")
    print(f"{'='*80}")
    print(f"Total APIs processed: {total_apis}")
    print(f"Total chunks: {total_chunks}")
    print(f"✅ Successful chunks: {successful_chunks}")
    print(f"❌ Failed chunks: {failed_chunks}")
    print(f"📈 Success rate: {(successful_chunks/total_chunks)*100:.1f}%")
    print(f"{'='*80}\n")
    
    # Return True if all chunks were successful
    return failed_chunks == 0 