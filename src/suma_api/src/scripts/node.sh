#!/bin/bash
'''

[Node Joining process]First nodes are joined with a very specific name and a label in the cluster using the join command. A admission webhook will make sure 
that the reuired conditions are met before a node joins. Naming the node let us know at we were expecting it. The labels 
make sure that the node is not schedules pods unknowingly. 
Once a node joins it is given a unique NodeAccesKey that can be used to switch groups. Access keys can be used only once. A new
key is generated once the existing one expires. 
**a regular garbage collector routine can be loaded that drains all nodes that were not expected.

Once a node joins it joins with a ownerID. Anyone with the owner ID will have access to describe the node 
and change options for expiry of accessKeys.


[User Joining]: User have control over a single resources SumaJob. This will be the primary and the only resource user
can create/delete/modify. 
-- users can add nodes to the job.
-- users can scedule ml jobs in the cluster on the nodes that he have access to. 

first user needs to verifiy itself to suma api and request a user certificate that he can use to access SumaJob resoruce
only. After that user can create/delete/update sumaJob. 

"
nodes:
    -name: user21
    -accessKey: ur9c3iuc8ry
    -name: user43
    -accessKey: weoifh89r9384
    -name: t2.micro         (LATER)
    -accessKey: fij34ut834ut
    
"
Creating sumaJob: This will internally first check is the node objects are free(and not already currentl running jobs)
It then labels node with a unique jobId and initialisez a namespace selecting nodes with the label id=jonID. It then 
sets the necessary kubeflow operators or deamon sets or configures necessary volumeClaims needed in the namespace. 
After the Job is finished resources are deleted and nodes accessKeys are chaged.
 '''

###

# Function to create a Validating Admission Webhook
create_validating_webhook() {
    cat <<EOF | kubectl apply -f -
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: validate-node-join
webhooks:
  - name: validate-node-join.suma.com
    rules:
      - apiGroups: ["*"]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["nodes"]
    clientConfig:
      service:
        name: suma-webhook-service
        namespace: default
        path: "/validate-node"
      caBundle: $(cat /path/to/ca.crt | base64 | tr -d '\n')
    admissionReviewVersions: ["v1"]
    sideEffects: None
EOF
}

# Function to create a Mutating Admission Webhook
create_mutating_webhook() {
    cat <<EOF | kubectl apply -f -
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: mutate-node-join
webhooks:
  - name: mutate-node-join.suma.com
    rules:
      - apiGroups: ["*"]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["nodes"]
    clientConfig:
      service:
        name: suma-webhook-service
        namespace: default
        path: "/mutate-###

ACTION=""
NODE_NAME=""
LABELS=""
FORCE=false
DRAIN_TIMEOUT="300s"

# Function to print usage instructions
print_usage() {
    echo "Usage: $0 -a <action> -n <node-name> [options]"
    echo ""
    echo "Actions:"
    echo "  label       Add/modify node labels"
    echo "  cordon      Mark node as unschedulable"
    echo "  uncordon    Mark node as schedulable"
    echo "  drain       Drain node (evict all pods)"
    echo "  delete      Delete node from cluster"
    echo ""
    echo "Required Options:"
    echo "  -a    Action to perform (required)"
    echo "  -n    Node name (required)"
    echo ""
    echo "Additional Options:"
    echo "  -l    Labels (format: key1=value1,key2=value2) - required for 'label' action"
    echo "  -f    Force action (skip confirmations)"
    echo "  -t    Drain timeout (default: 300s)"
    echo "  -h    Show this help message"
    echo ""
    echo "Examples:"
    echo "  Add labels:"
    echo "    $0 -a label -n worker1 -l env=prod,role=worker"
    echo ""
    echo "  Cordon node:"
    echo "    $0 -a cordon -n worker1"
    echo ""
    echo "  Drain node:"
    echo "    $0 -a drain -n worker1 -t 600s"
    exit 1
}

# Function to validate input
validate_input() {
    if [[ -z "$ACTION" ]]; then
        echo "Error: Action must be specified with -a"
        exit 1
    fi

    if [[ -z "$NODE_NAME" ]]; then
        echo "Error: Node name must be specified with -n"
        exit 1
    fi

    if [[ "$ACTION" == "label" && -z "$LABELS" ]]; then
        echo "Error: Labels must be specified with -l when using label action"
        exit 1
    fi

    # Verify node exists
    if ! kubectl get node "$NODE_NAME" &>/dev/null; then
        echo "Error: Node '$NODE_NAME' not found in cluster"
        exit 1
    fi
}

# Function to confirm action
confirm_action() {
    local action=$1
    local node=$2
    
    if [[ "$FORCE" == true ]]; then
        return 0
    fi

    read -p "Are you sure you want to $action node '$node'? (y/n): " answer
    if [[ "$answer" != "y" ]]; then
        echo "Operation cancelled"
        exit 0
    fi
}

# Function to label node
label_node() {
    echo "Adding labels to node: $NODE_NAME"
    
    local label_args=""
    IFS=',' read -ra LABEL_PAIRS <<< "$LABELS"
    for pair in "${LABEL_PAIRS[@]}"; do
        label_args="$label_args $pair"
    done
    
    kubectl label node "$NODE_NAME" $label_args --overwrite
    
    echo "Labels added successfully"
    kubectl get node "$NODE_NAME" --show-labels
}

# Function to cordon node
cordon_node() {
    confirm_action "cordon" "$NODE_NAME"
    echo "Cordoning node: $NODE_NAME"
    kubectl cordon "$NODE_NAME"
    echo "Node cordoned successfully"
}

# Function to uncordon node
uncordon_node() {
    confirm_action "uncordon" "$NODE_NAME"
    echo "Uncordoning node: $NODE_NAME"
    kubectl uncordon "$NODE_NAME"
    echo "Node uncordoned successfully"
}

# Function to drain node
drain_node() {
    confirm_action "drain" "$NODE_NAME"
    echo "Draining node: $NODE_NAME"
    echo "Timeout set to: $DRAIN_TIMEOUT"
    
    kubectl drain "$NODE_NAME" \
        --ignore-daemonsets \
        --delete-emptydir-data \
        --timeout="$DRAIN_TIMEOUT" \
        --force
    
    echo "Node drained successfully"
}

# Function to delete node
delete_node() {
    confirm_action "DELETE" "$NODE_NAME"
    
    echo "WARNING: This will remove the node from the cluster"
    if [[ "$FORCE" != true ]]; then
        read -p "Type the node name '$NODE_NAME' to confirm deletion: " confirmation
        if [[ "$confirmation" != "$NODE_NAME" ]]; then
            echo "Node name mismatch. Operation cancelled"
            exit 1
        fi
    fi

    echo "Deleting node: $NODE_NAME"
    kubectl delete node "$NODE_NAME"
    echo "Node deleted successfully"
}

# Parse command line arguments
while getopts "a:n:l:t:fh" opt; do
    case $opt in
        a)
            ACTION="$OPTARG"
            ;;
        n)
            NODE_NAME="$OPTARG"
            ;;
        l)
            LABELS="$OPTARG"
            ;;
        t)
            DRAIN_TIMEOUT="$OPTARG"
            ;;
        f)
            FORCE=true
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

# Validate inputs
validate_input

# Execute requested action
case "$ACTION" in
    label)
        label_node
        ;;
    cordon)
        cordon_node
        ;;
    uncordon)
        uncordon_node
        ;;
    drain)
        drain_node
        ;;
    delete)
        delete_node
        ;;
    *)
        echo "Error: Invalid action '$ACTION'"
        print_usage
        ;;
esac