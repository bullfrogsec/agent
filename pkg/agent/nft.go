package agent

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

//go:embed queue_audit.nft
var auditRules string

//go:embed queue_block.nft
var blockRules string

// renderRules produces the ruleset to hand to nft.
//
// The block ruleset is a template carrying injectionMarkPlaceholder, which is
// replaced with this run's mark. Audit mode injects no packets, so it has no
// placeholder to fill in.
func renderRules(egressPolicy string) string {
	if egressPolicy != EGRESS_POLICY_BLOCK {
		return auditRules
	}
	return strings.ReplaceAll(blockRules, injectionMarkPlaceholder,
		fmt.Sprintf("0x%08x", injectedPacketMark))
}

// LoadNftRules writes the appropriate nftables rules to a temp file and loads them.
func LoadNftRules(egressPolicy string) error {
	rules := renderRules(egressPolicy)

	tmpFile, err := os.CreateTemp("", "bullfrog-*.nft")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	// The rendered ruleset contains this run's injection mark, and anything
	// that can read the mark can use the rule that lets it through. Nothing
	// needs the file once nft has loaded it.
	defer os.Remove(tmpPath)

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
