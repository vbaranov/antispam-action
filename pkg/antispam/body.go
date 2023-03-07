package antispam

import "strings"

func checkText(body string) []Detection {
	var detections []Detection
	if strings.Contains(body, ".ru/") {
		detections = append(detections, Detection{
			Location:       "body",
			DebugInfo:      "Body contains an ru domain URL",
			AuthorFeedback: "Please do not include URLs with ru domains.",
		})
	}
	return detections
}
