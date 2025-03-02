package antispam

import (
	"slices"
	"strings"
)

func checkText(str string, location string) []Detection {
	var detections []Detection
	str_lower_case := strings.ToLower(str)
	patterns := []string{
		"my transaction failed", "not credited", "never credited", "did not recieve payment",
		"mistakenly send", "mistakenly sent", "transaction mistake", "by mistake sent",
		"wrong network", "wrong wallet address", "wrong blockchain address", "wrong send coin",
		"assets stuck", "asset not deposited", "not receive", "haven't received",
		"withdraw not received", "failed transfer", "not yet received", "not been received",
		"didn't received", "transfer was not successful", "sent fund", "crypto transfer",
		"crypto deposit", "send crypto", "lost crypto", "crypto lost", "made a deposit",
		"made a transfer", "i transfer", "i swap", "i have transferred", "i don't receive",
		"i didn't receive", "binance", "coinbase wallet", "exchange", "transaction has not arrived",
		"cex wallet", "received my ethereum", "transaction not successful", "transaction not receiped",
		"wrong deposit", "wrong transaction", "transaction still pending", "refund", "faucet sent",
	}

	for _, pattern := range patterns {
		if strings.Contains(str_lower_case, pattern) {
			detections = append(detections, Detection{
				Location:       location,
				DebugInfo:      "Body contains info of failed transfer",
				AuthorFeedback: "Thank you for reporting; please note Blockscout is only an explorer and cannot manage transactions—contact your wallet provider or dApp for assistance.",
			})
			break
		}
	}
	return detections
}

func removeDuplicates(sliceList []Detection) []string {
	var reasons []string
	for i := range sliceList {
		reasons = append(reasons, sliceList[i].AuthorFeedback)
	}
	slices.Sort(reasons)
	return slices.Compact(reasons)
}
