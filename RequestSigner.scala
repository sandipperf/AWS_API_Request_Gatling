package NewOrder_AWS

import java.net.{URI, URLEncoder}
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.{ZoneId, ZonedDateTime}
import java.time.format.DateTimeFormatter

import com.amazonaws.auth.{AWSCredentials, AWSSessionCredentials}
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.apache.commons.codec.binary.Hex
import org.apache.commons.lang3.StringUtils
import scala.collection.Seq


case class AWSSignature(xAmzSecurityToken: Option[String], xAmzDate: String, authorisationSignature: String)

case class Header(key: String, values: List[String])

case class QueryParam(name: String, value: String)

case class Request(headers: Seq[Header],
                   body: Option[String],
                   method: String,
                   private val uriPath: String,
                   queryParameters: Seq[QueryParam] = Seq.empty[QueryParam]) {
  val cleanedUriPath = uriPath.replaceFirst("""^//""", "/")
}

object RequestSigner {


  def sign(uriPath: String,
           method: String,
           body: Option[String],
           headers: Seq[(String, List[String])],
           queryParameters: Seq[(String, String)] = Seq.empty[(String, String)],
           requestDate: ZonedDateTime = ZonedDateTime.now(ZoneId.of("UTC")),
           credentials: AWSCredentials, region: String, service: String): AWSSignature = {

    val requestHeaders = headers.map {
      case (header, headerValues) => Header(header, headerValues)
    }

    val request = Request(requestHeaders, body, method, uriPath, queryParameters.map(a => QueryParam(a._1, a._2)))

    val canonicalRequest = RequestSigner.CanonicalRequestBuilder.buildCanonicalRequest(request)

    val stringToSign = RequestSigner.StringToSignBuilder.buildStringToSign(
      region = region,
      service = service,
      canonicalRequest = canonicalRequest,
      requestDate = requestDate)

    RequestSigner.StringSigner.buildAwsSignature(
      stringToSign = stringToSign,
      requestDate = requestDate,
      credentials = credentials,
      service = service,
      region = region,
      headers = request.headers)
  }

  val DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")

  val DATE_FORMATTER_DATE_ONLY = DateTimeFormatter.ofPattern("yyyyMMdd")


  object CanonicalRequestBuilder {
    private val emptyBody = "".getBytes(StandardCharsets.UTF_8)

    private val headerToCanonicalString = (header: Header) => {
      val headerValues = header.values.map(headerValue => headerValue.split("\n").map(StringUtils.normalizeSpace).mkString(","))
      s"${header.key.toLowerCase}:${headerValues.mkString(",")}"
    }

    def buildCanonicalRequest(request: Request): String = {
      if (!request.headers.exists(_.key.toLowerCase == "host"))
        throw new IllegalArgumentException(s"Could not build canonical request, 'Host' header required, request=$request")

      val canonicalQueryParams = request.queryParameters.sortBy(_.name).map {
        case QueryParam(name, value) => s"${specialUrlEncode(name)}=${specialUrlEncode(value)}"
      }.mkString("&")

      val sortedHeaders = request.headers.sortBy(_.key)
      val canonicalHeaders = sortedHeaders.map(headerToCanonicalString).mkString("\n")
      val canonicalSignedHeaders = sortedHeaders.map(_.key.toLowerCase).mkString(";")

      val bodyBytes = request.body.map(_.getBytes).getOrElse(emptyBody)
      val hexEncodedPayloadHash = Hex.encodeHexString(sha256Hash(bodyBytes))

      val normalizedPath = new URI(null, null, request.cleanedUriPath, null).normalize().toASCIIString

      val canonicalRequest = Seq(request.method, normalizedPath, canonicalQueryParams, canonicalHeaders, "",
        canonicalSignedHeaders, hexEncodedPayloadHash)

      canonicalRequest.mkString("\n")
    }

    private def specialUrlEncode(str: String) = {
      urlEncode(str)
        .replace("+", "%20")
        .replace("*", "%2A")
        .replace("%7E", "~")
    }
  }

  object StringToSignBuilder {

    def buildStringToSign(region: String, service: String, canonicalRequest: String, requestDate: ZonedDateTime) = {

      val credentialsScope = s"${requestDate.format(DATE_FORMATTER_DATE_ONLY)}/$region/$service/aws4_request"

      val hexEncodedCanonicalRequestHash = Hex.encodeHexString(sha256Hash(canonicalRequest.getBytes))
      val stringToSign = Seq(
        "AWS4-HMAC-SHA256",
        requestDate.format(DATE_FORMATTER),
        credentialsScope,
        hexEncodedCanonicalRequestHash)
        .mkString("\n")

      stringToSign
    }
  }

  object StringSigner {
    def buildAwsSignature(stringToSign: String,
                          requestDate: ZonedDateTime,
                          credentials: AWSCredentials,
                          service: String,
                          region: String,
                          headers: Seq[Header]): AWSSignature = {
      val credentialsScope = s"${requestDate.format(DATE_FORMATTER_DATE_ONLY)}/$region/$service/aws4_request"
      val canonicalSignedHeaders = headers.sortBy(_.key).map(e => e.key.toLowerCase).mkString(";")
      val signature = encryptWithHmac256(stringToSign, requestDate, credentials, region, service)
      val authSignature = s"AWS4-HMAC-SHA256 Credential=${credentials.getAWSAccessKeyId}/$credentialsScope, SignedHeaders=$canonicalSignedHeaders, Signature=$signature"

      val securityToken = credentials match {
        case creds: AWSSessionCredentials => Some(creds.getSessionToken)
        case _ => None
      }

      AWSSignature(xAmzSecurityToken = securityToken,
        xAmzDate = requestDate.format(DATE_FORMATTER),
        authorisationSignature = authSignature)
    }

    private def encryptWithHmac256(stringToSign: String,
                                   requestDate: ZonedDateTime,
                                   credentials: AWSCredentials,
                                   region: String,
                                   service: String): String = {

      def encrypt(data: String, key: Array[Byte]): Array[Byte] = {
        val hmacSha256 = "HmacSHA256"
        val mac = Mac.getInstance(hmacSha256)
        mac.init(new SecretKeySpec(key, hmacSha256))
        mac.doFinal(data.getBytes(StandardCharsets.UTF_8))
      }

      def getSignatureKey(now: ZonedDateTime, credentials: AWSCredentials): Array[Byte] = {
        val kSecret = s"AWS4${credentials.getAWSSecretKey}".getBytes(StandardCharsets.UTF_8)

        Seq(now.format(DATE_FORMATTER_DATE_ONLY), region, service, "aws4_request").foldLeft(kSecret) {
          (acc, value) => encrypt(value, acc)
        }
      }

      Hex.encodeHexString(encrypt(stringToSign, getSignatureKey(requestDate, credentials)))
    }
  }


  private def urlEncode(value: String) = URLEncoder.encode(value, "UTF-8")

  private def sha256Hash(payload: Array[Byte]): Array[Byte] = {
    val md: MessageDigest = MessageDigest.getInstance("SHA-256")
    md.update(payload)
    md.digest
  }
}

