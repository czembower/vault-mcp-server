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

type Mount struct {
	Name            string `json:"name"`              // Name of the mount
	Type            string `json:"type"`              // Type of the mount (e.g., kv, kv2)
	Description     string `json:"description"`       // Description of the mount, if any
	DefaultLeaseTTL int    `json:"default_lease_ttl"` // Default lease TTL for the mount, if any
	MaxLeaseTTL     int    `json:"max_lease_ttl"`     // Max lease TTL for the mount, if any
}

// ListMounts creates a tool for listing Vault mounts
func ListMounts(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_mounts",
			mcp.WithDescription("List the available mounted secrets engines on a Vault Server."),
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					IdempotentHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithString("namespace",
				mcp.DefaultString(""),
				mcp.Description("Namespace path to list mounts from (e.g., 'admin/' or empty for root). Defaults to current namespace.")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listMountHandler(ctx, req, logger)
		},
	}
}

func listMountHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling list_mounts request")

	// Extract parameters
	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	namespace, _ := args["namespace"].(string)

	logger.WithFields(log.Fields{
		"namespace": namespace,
	}).Debug("Listing mounts")

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

	// List mounts from Vault
	mounts, err := nsClient.Sys().ListMounts()
	if err != nil {
		logger.WithError(err).Error("Failed to list mounts")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list mounts: %v", err)), nil
	}

	var results []*Mount
	for k, v := range mounts {
		mount := &Mount{
			Name:            k,
			Type:            v.Type,
			Description:     v.Description,
			DefaultLeaseTTL: v.Config.DefaultLeaseTTL,
			MaxLeaseTTL:     v.Config.MaxLeaseTTL,
		}
		results = append(results, mount)
	}

	// Marshal the struct to JSON
	jsonData, err := json.Marshal(results)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal mounts to JSON")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	logger.WithField("mount_count", len(results)).Debug("Successfully listed mounts")
	return mcp.NewToolResultText(string(jsonData)), nil
}
