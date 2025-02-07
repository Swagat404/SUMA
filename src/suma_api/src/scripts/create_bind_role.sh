#!/bin/bash

#need to be more defensive. And ability to apply a series of roles. delete roles. patch roles. 
#create/delte/patch rolebindigns
# Script to create a Kubernetes role and bind it to a user.
# Usage: ./create_role_and_binding.sh <role_name> <namespace> <username>

# Exit the script if any command fails
set -e

# Variables
ROLE_NAME="$1"
NAMESPACE="$2"
USERNAME="$3"

# Function to display an error message and exit
error_exit() {
  echo "[ERROR] $1" >&2
  exit 1
}

# Function to check dependencies
check_dependencies() {
  command -v kubectl >/dev/null 2>&1 || error_exit "kubectl is not installed. Please install it."
}

# Ensure required arguments are provided
if [[ -z "$ROLE_NAME" || -z "$NAMESPACE" || -z "$USERNAME" ]]; then
  error_exit "Usage: $0 <role_name> <namespace> <username>"
fi

# Check for required tools
check_dependencies

# Step 1: Create the Role
echo "Creating role $ROLE_NAME in namespace $NAMESPACE..."
cat <<EOF | kubectl  apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: $NAMESPACE
  name: $ROLE_NAME
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "configmaps"]
    verbs: ["get", "list", "watch", "create", "delete"]
  - apiGroups: ["apps"]
    resources: ["deployments", "replicasets"]
    verbs: ["get", "list", "watch", "create", "delete"]
EOF

if [[ $? -ne 0 ]]; then
  error_exit "Failed to create role $ROLE_NAME."
fi

# Step 2: Create the RoleBinding
echo "Binding role $ROLE_NAME to user $USERNAME in namespace $NAMESPACE..."
cat <<EOF | kubectl  apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${ROLE_NAME}-binding
  namespace: $NAMESPACE
subjects:
  - kind: User
    name: $USERNAME
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: $ROLE_NAME
  apiGroup: rbac.authorization.k8s.io
EOF

if [[ $? -ne 0 ]]; then
  error_exit "Failed to bind role $ROLE_NAME to user $USERNAME."
fi

# Final message
echo "Role $ROLE_NAME and RoleBinding ${ROLE_NAME}-binding have been successfully created in namespace $NAMESPACE for user $USERNAME."
