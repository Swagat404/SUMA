#include <config/kube_config.h>
#include <include/apiClient.h>
#include <include/generic.h>
#include <malloc.h>
#include <stdio.h>
#include <errno.h>
#include "ssl.h"
/**
First step: check if a node exists in the cluster. monitor it's status. 

Creating/deleting/pathcing(NodeSelector) namespaces
Creating/delete/patching role
Crating/deleting/patching rolebinding


*/


int main(int argc, char *argv[])
{


    char *basePath = NULL;
    sslConfig_t *sslConfig = NULL;
    list_t *apiKeys = NULL;
    int rc = load_kube_config(&basePath, &sslConfig, &apiKeys, NULL);   /* NULL means loading configuration from $HOME/.kube/config */
    if (rc != 0) {
        printf("Cannot load kubernetes configuration.\n");
        return -1;
    }
    apiClient_t *apiClient = apiClient_create_with_base_path(basePath, sslConfig, apiKeys);
    if (!apiClient) {
        printf("Cannot create a kubernetes client.\n");
        return -1;
    }

/*
we will load a generic template for theses yamls and store them in structs provided by tthe documenation.after that we can directly operate with 
those structs. I think there are even lib that can convert yamls to structs and structs to yaml.
*/
 genericClient_t *genericClient = genericClient_create(apiClient, "rbac.authorization.k8s.io", "v1", "namespaces/test/roles");

    const char *body = "{"
    "\"apiVersion\": \"rbac.authorization.k8s.io/v1\","
    "\"kind\": \"Role\","
    "\"metadata\": {"
        "\"name\": \"readonly-role\","
        "\"namespace\": \"test\""
    "},"
    "\"rules\": ["
        "{"
            "\"apiGroups\": [\"\"],"
            "\"resources\": [\"pods\", \"services\", \"configmaps\", \"secrets\"],"
            "\"verbs\": [\"get\", \"list\", \"watch\"]"
        "},"
        "{"
            "\"apiGroups\": [\"apps\"],"
            "\"resources\": [\"deployments\"],"
            "\"verbs\": [\"get\", \"list\", \"watch\"]"
        "}"
    "]"
"}";

    char *create = Generic_createResource(genericClient, body);
    printf("%s\n", create);
    free(create);

    genericClient_free(genericClient);
    genericClient = NULL;

    apiClient_free(apiClient);
    apiClient = NULL;
    free_client_config(basePath, sslConfig, apiKeys);
    basePath = NULL;
    sslConfig = NULL;
    apiKeys = NULL;
    apiClient_unsetupGlobalEnv();

    return 0;
}