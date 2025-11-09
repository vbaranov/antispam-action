package antispam

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	translator "github.com/Conight/go-googletrans"
)

var whitelisted_logins = map[string]bool{}

// translateToEnglish attempts to translate text to English if it's not already in English
func translateToEnglish(text string) string {
	// Skip translation if text is already mostly English (contains common English words)
	englishWords := []string{"transaction", "failed", "not", "received", "crypto", "wallet", "funds", "deposit", "withdraw", "pending", "successful", "error", "problem", "help", "please", "thank", "you", "the", "and", "or", "but", "is", "are", "was", "were", "have", "has", "had", "will", "can", "could", "should", "would", "may", "might", "must", "need", "want", "get", "send", "receive", "make", "do", "go", "come", "see", "know", "think", "say", "tell", "ask", "give", "take", "put", "find", "look", "work", "use", "try", "call", "move", "turn", "start", "stop", "open", "close", "buy", "sell", "pay", "cost", "price", "money", "time", "day", "week", "month", "year", "today", "yesterday", "tomorrow", "now", "here", "there", "where", "when", "how", "why", "what", "who", "which", "this", "that", "these", "those", "my", "your", "his", "her", "its", "our", "their", "me", "you", "him", "us", "them", "i", "we", "they", "he", "she", "it"}

	textLower := strings.ToLower(text)
	englishWordCount := 0
	for _, word := range englishWords {
		if strings.Contains(textLower, word) {
			englishWordCount++
		}
	}

	// If we find 3+ English words, assume it's already in English
	if englishWordCount >= 3 {
		return text
	}

	// Attempt translation using Google Translate web API
	done := make(chan string, 1)
	go func() {
		translated, err := translateWithGoogle(text)
		if err != nil {
			fmt.Printf("Translation failed: %v\n", err)
			done <- text // Return original text if translation fails
		} else {
			done <- translated
		}
	}()

	select {
	case result := <-done:
		return result
	case <-time.After(5 * time.Second):
		fmt.Printf("Translation timeout, using original text\n")
		return text
	}
}

// translateWithGoogle uses go-googletrans to translate text to English
func translateWithGoogle(text string) (string, error) {
	t := translator.New()
	result, err := t.Translate(text, "auto", "en")
	if err != nil {
		return "", err
	}
	return result.Text, nil
}

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
		// Translate to English first, then convert to lowercase for pattern matching
		translatedText := translateToEnglish(str)
		fmt.Printf("Translated text: %s\n", translatedText)
		str_lower_case := strings.ToLower(translatedText)
		patterns := []string{
			// Funds not received / transaction issues (expanded)
			"transaction failed", "transaction not successful", "unsuccessful transaction", "failed transfer", "transfer failed", "transfer was not successful",
			"transfer taking very long time", "transfer taking too long", "transfer taking a long time",
			"transaction didn't go", "i was debited", "didn’t transfer", "hasn’t transferred",
			"reverted", "execution reverted", "tx reverted", "contract execution failed", "status failed",
			"not credited", "never credited", "credit not appearing", "deposit confirmed but not credited", "confirmed on chain not credited",
			"did not recieve payment", "did not receive payment", "payment not received", "not get payment", "not receiving money",
			"not receive", "haven't received", "has not arrived", "has not yet arrived", "hasn't arrived", "not yet received", "not been received", "i don't receive", "i didn't receive", "recipient didn't receive", "didn't received",
			"did not arrive", "didn't get the token", "token not received",
			"missing transaction", "transaction pending", "transaction still pending", "stuck on pending", "pending for hours", "pending for days",
			"0 confirmations", "zero confirmations", "confirmations not increasing", "unconfirmed transaction",
			"transaction dropped", "tx dropped", "dropped and replaced", "replace-by-fee",
			"nonce too low", "replacement transaction underpriced", "underpriced",
			"insufficient gas", "out of gas", "intrinsic gas too low", "gas too low", "max fee too low", "max priority fee too low",
			"assets stuck", "funds not reflected", "balance not updating", "balance zero", "wallet shows zero",
			"missing coins", "missing deposit", "missing eth",
			"made a deposit", "made a transfer", "i transfer", "i have transferred", "sent fund", "sent a coin", "crypto transfer", "crypto deposit", "send crypto",
			"wrong network", "wrong chain", "wrong chain id", "wrong wallet address", "wrong blockchain address", "wrong address", "wrong deposit", "wrong transaction", "wrong send coin", "send to wrong", "send by mistake", "by mistake sent", "mistakenly send", "mistakenly sent", "transaction mistake", "wrongly transfer",
			"withdraw not received", "withdraw issue", "withdrawal not delivered", "pending withdrawal", "made a withdrawal", "receive my withdrawal", "received my withdrawal", "withdraw money",
			"bridge failed", "bridge not received", "bridge stuck", "bridge pending", "bridge success but not received",
			"can not swap", "can't swap", "cannot swap", "swap failed", "swap pending", "swap not received", "i swap",
			"claim failed", "can not claim", "can't claim", "ineligible to claim", "want to claim",
			"see tokens in metamask", "token not visible", "can't see tokens", "cannot see tokens", "received my ethereum",
			"where is my crypto", "where are my funds", "rejection of funds", "was debited from my wallet",
			"tx not found", "transaction not found", "hash not found", "cannot find transaction", "can't find transaction",
			"internal tx not shown", "transfer event missing", "logs not found",
			"wrong memo", "missing memo", "missing tag",
			"binance", "gcash", "kucoin", "coinex", "bitget", "coinbase wallet", "bybit", "okx", "kraken", "huobi", "gate.io", "mexc", "crypto.com",
			"metamask", "trust wallet", "phantom", "trezor", "ledger", "ledger live", "cex wallet",
			"faucet sent", "refund", "no successful transaction", "transaction not receiped", "lost crypto", "crypto lost",
			"not deposited", "get my funds", "i lose", "i buy", "sending money", "my money", "sent money", "money sent", "lost payment", "i bought",
			"mistakenly wrong token", ": <issue title>", "not recive the token", "trader has been pending", "i made a mistake",
			"recover the fund", "fund is not in my", "cancel the transaction", "i withrawed", "withdrawal failed", "cancel transaction",
			"successful transaction but not delivered", "pending transaction", "send to etherum",
		}

		for _, pattern := range patterns {
			if strings.Contains(str_lower_case, pattern) {
				detections = append(detections, Detection{
					Location:       location,
					DebugInfo:      "Body indicates funds not received / transaction issue",
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
