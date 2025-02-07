#!/bin/bash

# Default values
CONFIG_FILE="namespace-config.conf"
DELETE_FLAG=false
NAMESPACE_NAME=""
CPU_LIMIT=""
MEMORY_LIMIT=""
ENABLE_NETWORK_POLICY=""
LABELS=""
NODE_SELECTOR=""
ANNOTATIONS=""

# Function to print usage instructions
print_usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -c    Specify config file (default: namespace-config.conf)"
    echo "  -d    Delete namespace instead of creating"
    echo "  -n    Namespace name (overrides config file)"
    echo "  -p    CPU limit (overrides config file)"
    echo "  -m    Memory limit (overrides config file)"
    echo "  -w    Enable network policy (true/false) (overrides config file)"
    echo "  -l    Labels (format: key1=value1,key2=value2)"
    echo "  -s    Node selector (format: key1=value1,key2=value2)"
    echo "  -a    Annotations (format: key1=value1,key2=value2)"
    echo "  -h    Show this help message"
    echo ""
    echo "Examples:"
    echo "  Create namespace with labels and node selector:"
    echo "    $0 -n my-namespace -l env=prod,team=backend -s location=dc2"
    echo ""
    echo "  Create with annotations:"
    echo "    $0 -n my-namespace -a description='Production namespace',owner='TeamA'"
    exit 1
}

# Function to read config file
read_config() {
    local config_file=$1
    if [[ ! -f "$config_file" ]]; then
        echo "Error: Config file '$config_file' not found"
        exit 1
    }

    # Read config file into variables if not overridden by command line
    while IFS='=' read -r key value; do
        # Skip empty lines and comments
        [[ -z "$key" || "$key" =~ ^[[:space:]]*# ]] && continue
        # Trim whitespace
        key=$(echo "$key" | tr -d '[:space:]')
        value=$(echo "$value" | tr -d '[:space:]')
        
        case "$key" in
            NAMESPACE_NAME)
                [[ -z "$NAMESPACE_NAME" ]] && NAMESPACE_NAME="$value"
                ;;
            CPU_LIMIT)
                [[ -z "$CPU_LIMIT" ]] && CPU_LIMIT="$value"
                ;;
            MEMORY_LIMIT)
                [[ -z "$MEMORY_LIMIT" ]] && MEMORY_LIMIT="$value"
                ;;
            ENABLE_NETWORK_POLICY)
                [[ -z "$ENABLE_NETWORK_POLICY" ]] && ENABLE_NETWORK_POLICY="$value"
                ;;
            LABELS)
                [[ -z "$LABELS" ]] && LABELS="$value"
                ;;
            NODE_SELECTOR)
                [[ -z "$NODE_SELECTOR" ]] && NODE_SELECTOR="$value"
                ;;
            ANNOTATIONS)
                [[ -z "$ANNOTATIONS" ]] && ANNOTATIONS="$value"
                ;;
        esac
    done < "$config_file"
}

# Function to convert comma-separated key-value pairs to YAML format
format_yaml_map() {
    local input=$1
    local indent=$2
    local IFS=','
    
    if [[ -n "$input" ]]; then
        echo
        for pair in $input; do
            key="${pair%%=*}"
            value="${pair#*=}"
            echo "${indent}${key}: ${value}"
        done
    fi
}

# Function to validate settings
validate_settings() {
    if [[ -z "$NAMESPACE_NAME" ]]; then
        echo "Error: Namespace name must be specified either in config file or via -n option"
        exit 1
    fi
}

# Function to create namespace
create_namespace() {
    echo "Creating namespace: $NAMESPACE_NAME"
    
    # Create namespace manifest with labels and annotations
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: $NAMESPACE_NAME$(format_yaml_map "$LABELS" "  labels:")$(format_yaml_map "$ANNOTATIONS" "  annotations:")
EOF

    # Apply node selector annotation if specified
    if [[ -n "$NODE_SELECTOR" ]]; then
        kubectl annotate namespace "$NAMESPACE_NAME" \
            "scheduler.alpha.kubernetes.io/node-selector=$NODE_SELECTOR" \
            --overwrite
    fi

    # Apply resource quotas if specified
    if [[ -n "$CPU_LIMIT" && -n "$MEMORY_LIMIT" ]]; then
        echo "Applying resource quotas (CPU: $CPU_LIMIT, Memory: $MEMORY_LIMIT)"
        cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ResourceQuota
metadata:
  name: resource-quota
  namespace: $NAMESPACE_NAME
spec:
  hard:
    cpu: "$CPU_LIMIT"
    memory: "$MEMORY_LIMIT"
EOF
    fi

    # Apply network policies if specified
    if [[ "$ENABLE_NETWORK_POLICY" == "true" ]]; then
        echo "Applying network policies"
        cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: $NAMESPACE_NAME
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
EOF
    fi

    echo "Namespace $NAMESPACE_NAME created successfully"
}

# Function to delete namespace
delete_namespace() {
    echo "Deleting namespace: $NAMESPACE_NAME"
    kubectl delete namespace "$NAMESPACE_NAME"
    echo "Namespace $NAMESPACE_NAME deleted successfully"
}

# Parse command line arguments
while getopts "c:dn:p:m:w:l:s:a:h" opt; do
    case $opt in
        c)
            CONFIG_FILE="$OPTARG"
            ;;
        d)
            DELETE_FLAG=true
            ;;
        n)
            NAMESPACE_NAME="$OPTARG"
            ;;
        p)
            CPU_LIMIT="$OPTARG"
            ;;
        m)
            MEMORY_LIMIT="$OPTARG"
            ;;
        w)
            ENABLE_NETWORK_POLICY="$OPTARG"
            ;;
        l)
            LABELS="$OPTARG"
            ;;
        s)
            NODE_SELECTOR="$OPTARG"
            ;;
        a)
            ANNOTATIONS="$OPTARG"
            ;;
        h)
            print_usage
            ;;
        \?)
            echo "Invalid option: -$OPTARG"
            print_usage
            ;;
    esac
done

# Main execution
# Read config file if it exists (command line options take precedence)
if [[ -f "$CONFIG_FILE" ]]; then
    read_config "$CONFIG_FILE"
fi

# Validate settings
validate_settings

# Execute requested operation
if [[ "$DELETE_FLAG" == true ]]; then
    delete_namespace
else
    create_namespace
fi