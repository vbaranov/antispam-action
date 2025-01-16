package antispam

import (
	"slices"
	"strings"
)

func checkText(str string, location string) []Detection {
	var detections []Detection
	str_lower_case := strings.ToLower(str)
	if strings.Contains(str_lower_case, "my transaction failed") ||
		strings.Contains(str_lower_case, "not credited") ||
		strings.Contains(str_lower_case, "never credited") ||
		strings.Contains(str_lower_case, "did not recieve payment") ||
		strings.Contains(str_lower_case, "mistakenly send") ||
		strings.Contains(str_lower_case, "transaction mistake") ||
		strings.Contains(str_lower_case, "by mistake sent") ||
		strings.Contains(str_lower_case, "wrong network") ||
		strings.Contains(str_lower_case, "wrong wallet address") ||
		strings.Contains(str_lower_case, "wrong blockchain address") ||
		strings.Contains(str_lower_case, "wrong send coin") ||
		strings.Contains(str_lower_case, "assets stuck") ||
		strings.Contains(str_lower_case, "asset not deposited") ||
		strings.Contains(str_lower_case, "not receive") ||
		strings.Contains(str_lower_case, "haven't received") ||
		strings.Contains(str_lower_case, "withdraw not received") ||
		strings.Contains(str_lower_case, "failed transfer") ||
		strings.Contains(str_lower_case, "not yet received") ||
		strings.Contains(str_lower_case, "not been received") ||
		strings.Contains(str_lower_case, "didn't received") ||
		strings.Contains(str_lower_case, "transfer was not successful") ||
		strings.Contains(str_lower_case, "sent fund") ||
		strings.Contains(str_lower_case, "crypto") ||
		strings.Contains(str_lower_case, "made a deposit") ||
		strings.Contains(str_lower_case, "made a transfer") ||
		strings.Contains(str_lower_case, "i transfer") ||
		strings.Contains(str_lower_case, "i swap") {
		detections = append(detections, Detection{
			Location:       location,
			DebugInfo:      "Body contains info of failed transfer",
			AuthorFeedback: "Thank you for reporting; please note Blockscout is only an explorer and cannot manage transactions—contact your wallet provider or dApp for assistance.",
		})
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
