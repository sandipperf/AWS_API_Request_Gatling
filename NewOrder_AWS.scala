package NewOrder_AWS

object Headers  {

	
val headers_01 = Map(
		"Host" -> "XXXXXX.execute-api.us-XXXX-2.amazonaws.com",
		"Content-Type" -> "application/json",
		//"test" -> "${signatureDetails}",
		"X-Amz-Date" -> "${amazonTimeDetails}",
		"Content-Length" -> "XXXXX",
		//"X-Amz-Date" -> "20190828T191952Z",
		//"Authorization" -> "AWS4-HMAC-SHA256 Credential=XXXXXXXXXX/20190828/us-XXXX-2/execute-api/aws4_request, SignedHeaders=host, Signature=XXXXXXXXXXXXXXXXXXXXXXX"
	"Authorization" -> "${signatureDetails}")
		
}
