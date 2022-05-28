package NewOrder_AWS

import RequestSigner._
import io.gatling.core.Predef._
import io.gatling.http.Predef._
import Headers._
import scala.collection._

import java.util.UUID.randomUUID
import util.Random.nextInt
import scala.util.Random
import java.io.File
import java.io.PrintWriter
import java.io.FileOutputStream


import com.amazonaws.auth.{BasicAWSCredentials, BasicSessionCredentials}

object NewOrder_AWS_Test {


  val uri01 = Configuration.Uri01
  var BatchId = new StringBuilder()
  var OrderId = new StringBuilder()
  
  val rnd = new Random()

  val scn = scenario("NewOrder_AWS")

    .repeat(100) {
    
         exec(session => session.set("batchId", ""))
        .exec(session => session.set("orderId", ""))
        .exec(session => session.set("signatureDetails", ""))
        .exec(session => session.set("amazonTimeDetails", ""))
        
        .exec(session => {
          BatchId.append(randomUUID().toString)
          OrderId.append("801g" + f"${rnd.nextInt(999999)}%06d" + rnd.alphanumeric.take(5).mkString)
          
           val requestBuildBody =
            s"""{
                 "batchId": "${BatchId}",
                 "orderId": "${OrderId}",
                }"""
                
          val AwsAccessKey = "XXXXXXXXXXXXXXX"
          val AwsSecretKey = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

          val signature = RequestSigner.sign(
          uriPath = "/your/url-01/details",

            method = "POST",
            body = Some(requestBuildBody),


            headers = Seq(("Host", List("XXXXXXXX.execute-api.us-XXXX-2.amazonaws.com"))),
            queryParameters = Seq.empty,
            credentials = new BasicAWSCredentials(AwsAccessKey, AwsSecretKey),
            region = "us-east-2",
            service = "execute-api")


          val amzStamp = (signature.toString).substring(18, 34)
          val sign = (signature.toString).substring(35, 223)
          session
            .set("signatureDetails", sign)
            .set("amazonTimeDetails", amzStamp)
        })
        
        .exec(session => session.set("batchId", BatchId))
        .exec(session => session.set("orderId", OrderId))
        
        .exec(session => {
          BatchId = new StringBuilder()
          OrderId = new StringBuilder()
          
          SignatureDetails = new StringBuilder()
          AmazonTimeDetails = new StringBuilder()

          session
        })
          .exec(http("Details_ppp")
          .post(uri01 + "/url01/process/details")
          .headers(headers_01)
          .body(ElFileBody("neworder_payload.json")).asJson)

}
}
