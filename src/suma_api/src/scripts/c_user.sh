#!/bin/bash

#much better way to do this is that we create a public service account with the only previllege to make csr requests to the api server
#While creating this service account a service account token can be requested with a particular expiry time (which can be rotated)
#this token can be given to users in the network and then csr request can be made.
# we can set admission control-webhooks to aproove this request (given that we were expecting this. essentially we make sure
# that the labels match in the csr request. the suma api retrieves the certificate once csr is approoved and gives back to the user)
#user now has admin access to his namespace.



####
#need to test more. meaningful results when the server is down/ or when error occured
#create/delte/patch csr. aproove/deny csr. 
set -e

# Load the configuration file
CONFIG_FILE="config.cfg"

# Function to load the configuration from the file
load_config() {
  if [[ -f "$CONFIG_FILE" ]]; then
    # Read the config file and export each variable
    while IFS='=' read -r key value; do
      if [[ ! "$key" =~ ^# && -n "$key" && -n "$value" ]]; then
        export "$key"="$value"
      fi
    done < "$CONFIG_FILE"
  else
    echo "[ERROR] Configuration file $CONFIG_FILE not found!" >&2
    exit 1
  fi
}

# Load config values
load_config

# Ensure required fields are set
if [[ -z "$CA_CERT_PATH" ]]; then
  echo "[ERROR] CA_CERT_PATH is not set in the configuration file." >&2
  exit 1
fi

# Set default values if not already set
USERNAME=${USERNAME:-$1}
GROUP=${GROUP:-default}
EXPIRY_TIME=${EXPIRY_TIME:-86400}
KUBERNETES_API_ADDRESS=${KUBERNETES_API_ADDRESS:-$2}
CA_CERT_PATH=${CA_CERT_PATH}
CONFIG_DIR=${CONFIG_DIR:-client-configs}
PRIVATE_KEY=${PRIVATE_KEY_PATH:-$USERNAME.pem}
CSR_FILE=${CSR_FILE_PATH:-$USERNAME.csr}
SIGNED_CERT=${SIGNED_CERT_PATH:-$USERNAME.crt}
CSR_NAME=${CSR_NAME:-$USERNAME}

# Ensure required arguments are provided
if [[ -z "$USERNAME" || -z "$KUBERNETES_API_ADDRESS" ]]; then
  echo "[ERROR] Usage: $0 <username> <kubernetes_api_address>"
  exit 1
fi


# Function to display an error message and exit
error_exit() {
  echo "[ERROR] $1" >&2
  rm user.*
  rm -r client-configs
  exit 1
}

# Function to check dependencies
check_dependencies() {
  command -v openssl >/dev/null 2>&1 || error_exit "OpenSSL is not installed. Please install it."
  command -v kubectl >/dev/null 2>&1 || error_exit "kubectl is not installed. Please install it."
}

# Check for required tools
check_dependencies


# Step 1: Generate private key for the user
echo "Generating private key for user $USERNAME..."
openssl genrsa -out $PRIVATE_KEY 2048 || error_exit "Failed to generate private key."

# Step 2: Create a Certificate Signing Request (CSR)
echo "Creating CSR for user $USERNAME..."
openssl req -new -key $PRIVATE_KEY -out $CSR_FILE -subj "/CN=$USERNAME/O=$GROUP" || error_exit "Failed to create CSR."

# Step 3: Base64 encode the CSR
BASE64_CSR=$(cat $CSR_FILE | base64 | tr -d "\n")

#anything above can be done on user end. I think even the certificate signing request can be done on user end. and only approval needs to 
#be done on the server. 

# Step 4: Create a Kubernetes CSR resource
cat <<EOF | kubectl  apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: $USERNAME
spec:
  request: $BASE64_CSR
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: $EXPIRY_TIME
  usages:
  - digital signature
  - key encipherment
  - client auth
EOF

# Step 5: Approve the CSR
echo "Approving CSR for user $USERNAME..."
kubectl certificate approve $USERNAME || error_exit "Failed to approve CSR."

# Step 6: Check CSR status and extract signed certificate
echo "Extracting signed certificate for user $USERNAME..."
kubectl get csr $USERNAME -o jsonpath="{.status.certificate}" | base64 -d > $SIGNED_CERT || error_exit "Failed to extract signed certificate."

# Step 7: Create a new kubeconfig file for the user
mkdir -p $CONFIG_DIR

# Set up cluster information
kubectl config set-cluster kubernetes \
  --kubeconfig=$CONFIG_DIR/$USERNAME-config \
  --server=$KUBERNETES_API_ADDRESS \
  --certificate-authority=ca.crt \
  --embed-certs=true || error_exit "Failed to set cluster information."


# Set user credentials
kubectl config set-credentials $USERNAME \
  --user=$USERNAME \
  --kubeconfig=$CONFIG_DIR/$USERNAME-config  \
  --client-certificate=$SIGNED_CERT \
  --client-key=$PRIVATE_KEY \
  --embed-certs=true || error_exit "Failed to set user credentials."

# Set context information
kubectl config set-context default \
  --user=$USERNAME \
  --kubeconfig=$CONFIG_DIR/$USERNAME-config \
  --cluster=kubernetes \
  --namespace=default || error_exit "Failed to set context information."

# Use the new context
kubectl config use-context default  --kubeconfig=$CONFIG_DIR/$USERNAME-config || error_exit "Failed to use new context."

# Final message
echo "User $USERNAME has been successfully created and configured."
echo "To use this user's kubeconfig, set the KUBECONFIG environment variable as follows:"
echo "export KUBECONFIG=$CONFIG_DIR/$USERNAME-config"
