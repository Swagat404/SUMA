#include <microhttpd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>


#define PORT 8888

#include <config/kube_config.h>
#include <api/CoreV1API.h>
#include <stdio.h>

char *list_pod(apiClient_t *apiClient) {
    v1_pod_list_t *pod_list = NULL;
    pod_list = CoreV1API_listNamespacedPod(apiClient, "kube-system",    /* namespace */
                                           NULL,    /* pretty */
                                           NULL,    /* allowWatchBookmarks */
                                           NULL,    /* continue */
                                           NULL,    /* fieldSelector */
                                           NULL,    /* labelSelector */
                                           NULL,    /* limit */
                                           NULL,    /* resourceVersion */
                                           NULL,    /* resourceVersionMatch */
                                           NULL,    /* sendInitialEvents */
                                           NULL,    /* timeoutSeconds */
                                           NULL     /* watch */
    );

    printf("The return code of HTTP request=%ld\n", apiClient->response_code);

    // Allocate a buffer for the result string
    size_t buffer_size = 1024;
    char *result = (char *)malloc(buffer_size);
    if (!result) {
        fprintf(stderr, "Memory allocation failed.\n");
        return NULL;
    }
    result[0] = '\0'; // Initialize as an empty string

    if (pod_list) {
        printf("Get pod list:\n");
        listEntry_t *listEntry = NULL;
        v1_pod_t *pod = NULL;

        list_ForEach(listEntry, pod_list->items) {
            pod = listEntry->data;

            // Calculate required space for the new pod name
            size_t required_space = strlen(pod->metadata->name) + 3; // +3 for "\n\0"
            if (strlen(result) + required_space >= buffer_size) {
                // Reallocate the buffer if needed
                buffer_size *= 2;
                char *temp = (char *)realloc(result, buffer_size);
                if (!temp) {
                    fprintf(stderr, "Memory reallocation failed.\n");
                    free(result);
                    v1_pod_list_free(pod_list);
                    return NULL;
                }
                result = temp;
            }

            // Append the pod name to the result string
            strcat(result, pod->metadata->name);
            strcat(result, "\n");
        }

        v1_pod_list_free(pod_list);
        pod_list = NULL;
    } else {
        printf("Cannot get any pod.\n");
        strcpy(result, "Cannot get any pod.\n");
    }

    return result;
}

static int
send_response (struct MHD_Connection *connection, const char *page)
{
  int ret;
  struct MHD_Response *response;


  response =
    MHD_create_response_from_buffer (strlen (page), (void *) page,
				     MHD_RESPMEM_PERSISTENT);
  if (!response)
    return MHD_NO;

  ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);

  return ret;
}


typedef struct {
    const char *method;
    const char *url;
    int (*handler)(struct MHD_Connection *, const char *);
} Route;
static int handle_create(struct MHD_Connection *connection, const char *method) {
    if (strcmp(method, "GET") != 0) {
        return send_response(connection, "Invalid method");
    }

    // Retrieve parameters from the query string
    const char *certificate = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "certificate");
    const char *resource = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "resource");

    // Validate required parameters
    //if (!certificate || !resource) {
    //    return send_response(connection, "Missing required parameters", MHD_HTTP_BAD_REQUEST);
    //}

    // Construct the response
    char *response = NULL;
    char *basePath = NULL;
    sslConfig_t *sslConfig = NULL;
    list_t *apiKeys = NULL;
    int rc = load_kube_config(&basePath, &sslConfig, &apiKeys, "/root/.kube/config");   /* NULL means loading configuration from $HOME/.kube/config */
    if (rc != 0) {
        printf("Cannot load kubernetes configuration.\n");
        return send_response(connection, "Cannot load kubernetes configuration");
    }
    
    apiClient_t *apiClient = apiClient_create_with_base_path(basePath, sslConfig, apiKeys);
    if (!apiClient) {
        printf("Cannot create a kubernetes client.\n");
        return send_response(connection, "Cannot create a kubernetes client");
    }

    response = list_pod(apiClient);  // Get the pod list as a string

    // Check if the response from list_pod is NULL
    if (!response) {
        apiClient_free(apiClient);
        free_client_config(basePath, sslConfig, apiKeys);
        apiClient_unsetupGlobalEnv();
        return send_response(connection, "Failed to fetch pod list");
    }

    // Send the response with the list of pods
    int ret = send_response(connection, response);

    // Clean up
    free(response);  // Free the dynamically allocated memory for the pod list
    apiClient_free(apiClient);
    free_client_config(basePath, sslConfig, apiKeys);
    apiClient_unsetupGlobalEnv();

    return ret;
}


static int handle_delete(struct MHD_Connection *connection, const char *method) {
    if (strcmp(method, "DELETE") != 0) {
        return send_response(connection, "Invalid method");
    }

    const char *certificate = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "certificate");
    const char *resource = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "resource");

    if (!certificate || !resource) {
        return send_response(connection, "Missing required parameters");
    }

    // TODO: Add logic for deleting the resource

    return send_response(connection, "success");
}

static Route routes[] = {
    {"GET", "/api/v1/create", handle_create},
    {"DELETE", "/api/v1/delete", handle_delete},
    {NULL, NULL, NULL} // Sentinel value to mark the end of the array
};

static int route_request(void *cls, struct MHD_Connection *connection, const char *url,
                         const char *method, const char *version, const char *upload_data,
                         size_t *upload_data_size, void **con_cls) {
    (void)cls;
    (void)version;
    (void)upload_data;
    (void)upload_data_size;
    (void)con_cls;

    for (Route *route = routes; route->method; route++) {
        if (strcmp(route->url, url) == 0 && strcmp(route->method, method) == 0) {
            return route->handler(connection, method);
        }
    }

    return send_response(connection, "101:Not found");
}

int main() {
    struct MHD_Daemon *daemon;

    daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, PORT, NULL, NULL,
                              &route_request, NULL, MHD_OPTION_END);

    if (!daemon) {
        fprintf(stderr, "Failed to start server\n");
        return 1;
    }

    printf("Server running on port %d\n", PORT);
    getchar(); // Wait for user input to stop the server

    MHD_stop_daemon(daemon);

    return 0;
}
