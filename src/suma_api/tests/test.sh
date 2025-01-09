#!/bin/bash

# API endpoint URL
API_URL="http://localhost:8888/api/v1/create"

# Parameters
CERTIFICATE="ayush@1euur32b8204fiehew"
RESOURCE="namespace"

# Send GET request
response=$(curl -s -G \
  -H "Content-Type: application/json" \
  -H "certificate: $CERTIFICATE" \
  --data-urlencode "resource=$RESOURCE" \
  "$API_URL")

# Print response
echo "API Response: $response"
