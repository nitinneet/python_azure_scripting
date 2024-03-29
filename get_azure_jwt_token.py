# ### az ad sp create-for-rbac --name free-trial-sp --create-cert ###
# from azure.identity import DefaultAzureCredential

# # Replace the value with the path to your certificate file
# CERTIFICATE_PATH = '/Users/admin/tmpojmg62vt.pem'

# # Create an instance of DefaultAzureCredential with certificate authentication
# credential = DefaultAzureCredential(
#     certificate_path=CERTIFICATE_PATH
# )

# # Use the credential to authenticate and obtain a token
# token = credential.get_token("https://vault.azure.net/.default")

# # Extract the JWT token from the token object
# jwt_token = token.token

# # Print the JWT token
# print("JWT Token:", jwt_token)

from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.core.exceptions import HttpResponseError

def get_azure_jwt_token(subscription_id):
    try:
        # Initialize Azure credentials
        credential = DefaultAzureCredential()

        # Authenticate to Azure subscription
        token = credential.get_token('https://management.azure.com/')

        # Extract the JWT token
        jwt_token = token.token

        print("##### Azure JWT token for Subscription:", subscription_id, "#####")

        return jwt_token

    except HttpResponseError as e:
        print("An error occurred while obtaining Azure JWT token for Subscription:", subscription_id)
        print("Error:", e)

        return None

def connect_to_azure_subscription(subscription_id):
    try:
        # Initialize Azure credentials
        credential = DefaultAzureCredential()

        # Initialize Resource Management client
        resource_client = ResourceManagementClient(credential, subscription_id)

        print("##### Successfully connected to Azure subscription:", subscription_id,"#####")

        return resource_client

    except HttpResponseError as e:
        print("An error occurred while connecting to Azure subscription:", subscription_id)
        print("Error:", e)

        return None

def validate_azure_subscription_connection(resource_client, subscription_id):
    if not resource_client:
        print(f"Failed to validate Azure subscription connection for Subscription: {subscription_id}. No resource client provided.")
        return False
    
    try:
        # List resource groups to validate connection
        resource_groups = resource_client.resource_groups.list()

        # If resource groups are listed without errors, the connection is successful
        print("##### Resource groups in the subscription #####")
        for rg in resource_groups:
            print("-", rg.name)

        return True

    except HttpResponseError as e:
        print(f"An error occurred while validating Azure subscription connection for Subscription: {subscription_id}.")
        print("Error:", e)

        return False

# Azure subscription ID
subscription_id = input("Enter Azure Subscription ID: ")

# Connect to Azure subscription
resource_client = connect_to_azure_subscription(subscription_id)

# Validate connection
if resource_client:
    connection_validated = validate_azure_subscription_connection(resource_client, subscription_id)
    if connection_validated:
        print("##### Azure subscription connection for Subscription:", subscription_id, "is valid #####")
    else:
        print("Failed to validate Azure subscription connection for Subscription:", subscription_id)
else:
    print("Failed to connect to Azure subscription for Subscription:", subscription_id)

# Get Azure JWT token
azure_jwt_token = get_azure_jwt_token(subscription_id)
if azure_jwt_token:
    print("##### Azure JWT token for Subscription:", subscription_id, "#####\n", azure_jwt_token)
