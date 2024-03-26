import json
import os
import requests
import toml

from urllib.parse import urlparse

# Define constants for the API host, API Key, and path to the TOML configuration file.
# These values are placeholders and should be replaced with actual data or read from environment variables.
TOML_FILE_PATH = 'photoniq_vwrs.toml' # VWRS domain configuration toml file path

# Define the headers for HTTP requests to the VWRS API, including authorization and content type.
VWRS_HEADERS = {
    'accept': 'application/json',
    'Authorization': 'your-vwrs-api-key',
    'Content-Type': 'application/json',
}

def read_toml_file(file_path):
    """Attempts to open and read the specified TOML file, returning its parsed content."""
    try:
        with open(file_path, 'r') as toml_file:
            return toml.load(toml_file)
    except FileNotFoundError:
        # Log an error if the file cannot be found at the specified path.
        print(f'Error: The file {file_path} was not found.')
    except toml.TomlDecodeError:
        # Log an error if the file content is not valid TOML format.
        print(f'Error: The file {file_path} contains invalid TOML.')
    except Exception as e:
        # Log any unexpected errors that occur during file reading.
        print(f'Unexpected error: {e}')
    return None

def print_response_content(response):
    """Print response content, if any."""
    if response.content:
            print(f'Response content: {response.content.decode("utf-8")}\n')

def get_domain(key):
    """Fetches an existing domain entry from VWRS API by a unique key."""
    try:
        response = requests.get(f'https://{VWRS_HOST}/api/vwr/v1/domains/{key}', headers=VWRS_HEADERS)
        response.raise_for_status()
        return response.json()
    except json.JSONDecodeError as e:
        # Failed to parse json.
        print(f'Failed to parse json response of GET for {key}: {e}')
        print_response_content(response)
    except requests.RequestException as e:
        # Log an error if there's an issue with the request to fetch the domain.
        print(f'Failed to read entry {key}: {e}')
        print_response_content(response)
    return None

def create_domain(entry):
    """Creates a new domain entry in VWRS via a POST request to the API."""
    try:
        response = requests.post(f'https://{VWRS_HOST}/api/vwr/v1/domains', json=entry, headers=VWRS_HEADERS)
        response.raise_for_status()
        # Log a success message with details from the API response.
        print(f'Entry added successfully: {response.json()}')
    except json.JSONDecodeError as e:
        # Failed to parse json.
        print(f'Failed to create entry, invalid JSON: {e}')
        print_response_content(response)
    except requests.RequestException as e:
        # Log an error if the POST request fails.
        print(f'Failed to create entry: {e}')
        print_response_content(response)


def update_domain(key, entry):
    """Updates an existing domain entry in VWRS via a PATCH request to the API."""
    try:
        response = requests.patch(f'https://{VWRS_HOST}/api/vwr/v1/domains/{key}', json=entry, headers=VWRS_HEADERS)
        response.raise_for_status()
        # Log a success message with details from the API response.
        print(f'Entry updated successfully: {response.json()}')
    except json.JSONDecodeError as e:
        # Failed to parse json.
        print(f'Failed to parse json response of PATCH for {key}: {e}')
        print_response_content(response)
    except requests.RequestException as e:
        # Log an error if the PATCH request fails.
        print(f'Failed to update entry {key}: {e}')
        print_response_content(response)

def process_entries(entries):
    """Processes each policy entry by either updating an existing entry or creating a new one."""
    for entry in entries:
        key = entry['domain_key']
        # Attempt to fetch an existing domain entry by its key.
        existing_entry = get_domain(key)
        if existing_entry:
            # If an entry exists, update it with the new data.
            update_domain(key, entry)
        else:
            # If no entry exists, create a new one.
            create_domain(entry)

def collect_domain_paths(policies):
    """Collect a set of all domain_url fields from a list of policies."""
    result = set() # The domain paths will be put here.
    for policy in policies:
        # Get the domain_url for a policy.
        domain_url = policy['domain_url']
        # Extract the path component and remove the leading slash.
        path = urlparse(domain_url).path.lstrip('/')
        # Add to the set.
        result.add(path)
    return result

def read_env_vars():
    """Read the necessary environment variables."""
    # Use global variables rather than declaring local ones.
    global VWRS_HOST, VWRS_API_KEY, TOML_FILE_PATH
    
    # Get TOML file path.
    TOML_FILE_PATH = os.getenv("TOML_FILE_PATH", TOML_FILE_PATH)
    
    # Get VWRS variables.
    VWRS_HOST = os.getenv("VWRS_HOST")
    VWRS_API_KEY = os.getenv("VWRS_API_KEY")
    
    # Check if the variables are None (not set) and handle accordingly
    if VWRS_HOST is None:
        print("Error: VWRS_HOST environment variable is not set.")
        raise EnvironmentError("VWRS_HOST environment variable is not set.")

    if VWRS_API_KEY is None:
        print("Error: VWRS_API_KEY environment variable is not set.")
        raise EnvironmentError("VWRS_API_KEY environment variable is not set.")

    # Use provided auth tokens.
    VWRS_HEADERS['Authorization'] = VWRS_API_KEY

def main():
    """Main function to execute the script logic."""

    # Read all the environment variables
    read_env_vars()

    print(VWRS_HEADERS)

    # Read and parse the TOML file specified by TOML_FILE_PATH.
    data = read_toml_file(TOML_FILE_PATH)
    if data and 'policies' in data:
        # Collect all the policies.
        policies = data['policies']
        # Process each policy.
        process_entries(policies)

if __name__ == '__main__':
    main()
