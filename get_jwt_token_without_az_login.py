#### Prececks #####
#### First create a service principle ####
#### run below command ####
#### az ad sp create-for-rbac --name free-trial-sp --create-cert ####
##### az keyvault certificate import --vault-name free-trial-new --name sp-new-pem-key --file /Users/admin/tmptde9wx6n.pem #####

from azure.identity import CertificateCredential, DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# Define Azure Key Vault URL
vault_url = "https://free-trial-new.vault.azure.net/"

# Name of the certificate secret imported into Azure Key Vault
certificate_secret_name = "sp-new-pem-key"

def login_using_certificate_from_keyvault(tenant_id, client_id, vault_url, certificate_secret_name):
    try:
        print("Attempting authentication using certificate from Key Vault...")
        
        # Create an instance of DefaultAzureCredential to authenticate with Azure services
        credential = DefaultAzureCredential()

        # Use the credential to authenticate and create a SecretClient to access Azure Key Vault
        client = SecretClient(vault_url=vault_url, credential=credential)

        # Retrieve the certificate bytes from the Key Vault
        certificate_secret = client.get_secret(certificate_secret_name)

        # Decode the certificate secret value (assuming it's base64 encoded)
        certificate_base64 = certificate_secret.value
        certificate_bytes = certificate_base64.encode("ascii")

        # Create a CertificateCredential using the decoded certificate bytes
        credential = CertificateCredential(tenant_id, client_id, certificate_data=certificate_bytes)
        
        print("Authentication successful.")
        return credential
    except Exception as e:
        print("An unexpected error occurred:", e)
        return None

def verify_login(credential):
    try:
        print("Verifying login status...")
        
        if credential:
            # Attempt to get a token to verify login status
            token = credential.get_token("https://vault.azure.net/.default")
            
            if token:
                print("User is logged in.")
                return True
            else:
                print("User is not logged in.")
                return False
        else:
            print("No credential provided.")
            return False
    except Exception as e:
        print("An unexpected error occurred while verifying login status:", e)
        return False

def main():
    # Set tenant_id and client_id variables
    tenant_id = ""
    client_id = ""

    # Authenticate using certificate from Key Vault
    credential = login_using_certificate_from_keyvault(tenant_id, client_id, vault_url, certificate_secret_name)

    if credential:
        # Obtain the JWT token
        token = credential.get_token("https://vault.azure.net/.default")
        if token:
            jwt_token = token.token
            print("JWT Token:", jwt_token)
        else:
            print("Failed to obtain JWT token.")
    else:
        print("Failed to authenticate using certificate from Key Vault.")

if __name__ == "__main__":
    main()
