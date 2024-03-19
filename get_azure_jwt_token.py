# from azure.identity import ClientSecretCredential

# # Set your Azure tenant ID, client ID, and client secret
# TENANT_ID = ''
# CLIENT_ID = ''
# CLIENT_SECRET = ''

# # Create a ClientSecretCredential object
# credential = ClientSecretCredential(TENANT_ID, CLIENT_ID, CLIENT_SECRET)

# # Obtain an access token
# access_token = credential.get_token("https://graph.microsoft.com/.default")

# # Extract the JWT token
# jwt_token = access_token.token

# print("JWT Token:", jwt_token)

from azure.identity import AzureCliCredential

# Create an AzureCliCredential object
credential = AzureCliCredential()

# Obtain an access token
access_token = credential.get_token("https://graph.microsoft.com/.default")

# Extract the JWT token
jwt_token = access_token.token

print("JWT Token:", jwt_token)
