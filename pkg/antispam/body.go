package antispam

import (
	"fmt"
	"os"
	"slices"
	"strings"
)

var whitelisted_logins = map[string]bool{}

func checkText(str string, location string, comment_author string) []Detection {
	fmt.Printf("comment author: %s\n", comment_author)
	fmt.Printf("env SCAM_ACTION_WHITELISTED_LOGINS value: %s\n", os.Getenv("SCAM_ACTION_WHITELISTED_LOGINS"))
	env_whitelisted_logins := os.Getenv("SCAM_ACTION_WHITELISTED_LOGINS")
	if env_whitelisted_logins != "" {
		for _, login := range strings.Split(env_whitelisted_logins, ",") {
			whitelisted_logins[strings.ToLower(strings.TrimSpace(login))] = true
		}
	}
	fmt.Printf("whitelisted_logins: %v\n", whitelisted_logins)
	var detections []Detection
	if !whitelisted_logins[strings.ToLower(comment_author)] {
		str_lower_case := strings.ToLower(str)
		patterns := []string{
			"my transaction failed", "not credited", "never credited", "did not recieve payment",
			"mistakenly send", "mistakenly sent", "transaction mistake", "by mistake sent",
			"wrong network", "wrong wallet address", "wrong blockchain address", "wrong send coin",
			"assets stuck", "not deposited", "not receive", "haven't received",
			"withdraw not received", "failed transfer", "not yet received", "not been received",
			"didn't received", "transfer was not successful", "sent fund", "sent a coin", "crypto transfer",
			"crypto deposit", "send crypto", "lost crypto", "crypto lost", "made a deposit",
			"made a transfer", "i transfer", "i swap", "i have transferred", "i don't receive",
			"i didn't receive", "binance", "kucoin", "bitget", "coinbase wallet", "bybit", "transaction has not arrived",
			"cex wallet", "received my ethereum", "transaction not successful", "transaction not receiped",
			"wrong deposit", "wrong transaction", "transaction still pending", "refund", "faucet sent", "wrongly transfer",
			"token did not arrive", "get my funds", "not get payment", "not receiving money", "transaction pending", "unsuccessful transaction", "didn't get the token", "credit not appearing",
			"missing eth", "see tokens in metamask", "can not swap", "i lose", "i buy", "send to wrong", "sending money", "claim failed", "ineligible to claim", "my money",
			"made a withdrawal", "receive my withdrawal", "can not claim", "lost payment",
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
	} else {
		fmt.Printf("Author is whitelisted: %s\n", comment_author)
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
