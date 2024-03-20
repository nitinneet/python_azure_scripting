#### First create a service principle ####
#### run below command ####
#### az ad sp create-for-rbac --name free-trial-sp --create-cert ####


from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import os

# Define Azure Key Vault URL
vault_url = "https://free-trial-new.vault.azure.net/"

# Name of the secret containing the certificate
certificate_secret_name = "sp-key"

# Create an instance of DefaultAzureCredential to authenticate with Azure services
credential = DefaultAzureCredential()

# Use the credential to authenticate and create a SecretClient to access Azure Key Vault
client = SecretClient(vault_url=vault_url, credential=credential)

# Retrieve the certificate secret from the Key Vault
certificate_secret = client.get_secret(certificate_secret_name)

# Decode the certificate secret value (assuming it's base64 encoded)
certificate_base64 = certificate_secret.value
certificate_bytes = certificate_base64.encode("ascii")
certificate_path = "/tmp/certificate.pem"  # Specify the path where you want to save the certificate

# Write the certificate bytes to a file
with open(certificate_path, "wb") as cert_file:
    cert_file.write(certificate_bytes)

# Create an instance of DefaultAzureCredential with certificate authentication
credential_with_cert = DefaultAzureCredential(certificate_path=certificate_path)

# Use the credential to authenticate and obtain a token
token = credential_with_cert.get_token("https://vault.azure.net/.default")

# Extract the JWT token from the token object
jwt_token = token.token

# Print the JWT token
print("JWT Token:", jwt_token)

# Remove the temporary certificate file
os.remove(certificate_path)
