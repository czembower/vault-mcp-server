// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

type Namespace struct {
	Path string `json:"path"` // Path of the namespace
}

// ListNamespaces creates a tool for listing Vault namespaces
func ListNamespaces(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_namespaces",
			mcp.WithDescription("List child namespaces within a Vault Enterprise namespace. Returns all child namespaces under the specified parent namespace path. Requires Vault Enterprise."),
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					IdempotentHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithString("namespace",
				mcp.DefaultString(""),
				mcp.Description("Parent namespace path to list namespaces from (e.g., 'admin/' or empty for root). Defaults to current namespace or root.")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listNamespacesHandler(ctx, req, logger)
		},
	}
}

func listNamespacesHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling list_namespaces request")

	// Extract parameters
	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	namespace, _ := args["namespace"].(string)

	logger.WithFields(log.Fields{
		"namespace": namespace,
	}).Debug("Listing namespaces")

	// Get Vault client from context
	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Create a new client instance with the specified namespace if provided
	nsClient := vault
	if namespace != "" {
		nsClient = vault.WithNamespace(namespace)
		logger.WithField("namespace", namespace).Debug("Using specified namespace")
	}

	// List namespaces from Vault
	// The API endpoint is sys/namespaces
	secret, err := nsClient.Logical().List("sys/namespaces")
	if err != nil {
		logger.WithError(err).Error("Failed to list namespaces")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list namespaces: %v (Note: This requires Vault Enterprise)", err)), nil
	}

	if secret == nil || secret.Data == nil {
		logger.Debug("No namespaces found")
		return mcp.NewToolResultText("[]"), nil
	}

	// Extract keys from the response
	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		logger.Warn("No 'keys' field in namespace list response")
		return mcp.NewToolResultText("[]"), nil
	}

	var results []*Namespace
	for _, key := range keys {
		if keyStr, ok := key.(string); ok {
			ns := &Namespace{
				Path: keyStr,
			}
			results = append(results, ns)
		}
	}

	// Marshal the struct to JSON
	jsonData, err := json.Marshal(results)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal namespaces to JSON")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	logger.WithField("namespace_count", len(results)).Debug("Successfully listed namespaces")
	return mcp.NewToolResultText(string(jsonData)), nil
}
