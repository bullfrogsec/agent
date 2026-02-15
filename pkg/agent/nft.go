package agent

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
)

//go:embed queue_audit.nft
var auditRules string

//go:embed queue_block.nft
var blockRules string

// LoadNftRules writes the appropriate nftables rules to a temp file and loads them.
func LoadNftRules(egressPolicy string) error {
	var rules string
	if egressPolicy == "block" {
		rules = blockRules
	} else {
		rules = auditRules
	}

	tmpFile, err := os.CreateTemp("", "bullfrog-*.nft")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	if _, err := tmpFile.WriteString(rules); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write nft rules: %w", err)
	}
	tmpFile.Close()

	cmd := exec.Command("nft", "-f", tmpPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to load nft rules: %w, output: %s", err, string(output))
	}

	return nil
}
