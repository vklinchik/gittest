

import bline.play.basicauth.{AuthenticationDataSource, HttpBasicAuthenticator}
import org.specs2.mutable._
import play.api.mvc.{Result, Results, Headers, RequestHeader}

import scala.concurrent.{Await, Future}
import scala.concurrent.duration._

class HttpBasicAuthenticatorSpec extends Specification {

  // --------   test data ---------------
  trait TestRequestHeader extends RequestHeader {
    override def id: Long = 1
    override def tags: Map[String, String] = Map()
    override def path: String = "/"
    override def method: String = "GET"
    override def version: String = "1.0"
    override def queryString: Map[String, Seq[String]] = Map()
    override def remoteAddress: String = "127.0.0.1"
    override def secure: Boolean = false
  }

  case class AuthNotSetRH(
    override val uri: String = "/index.html",
    override val headers: Headers = Headers(("", ""), ("x-forwarded-for", "127.1.1.1"))
  ) extends TestRequestHeader

  case class InvalidCredentialsRH(
    override val uri: String = "/index.html",
    override val headers: Headers = Headers(("Authorization", "Basic YWRtaW46aGVsbG8="), ("x-forwarded-for", "127.1.1.1"))
  ) extends TestRequestHeader


  case class ValidRequestRH(
    override val uri: String = "/index.html",
    override val headers: Headers = Headers(("Authorization", "Basic YWRtaW46cGFzc3dvcmQ="), ("x-forwarded-for", "127.1.1.1"))
  ) extends TestRequestHeader

  case class ExcludedResourceRH(
    override val uri: String = "/about.html",
    override val headers: Headers = Headers(("Authorization", "Basic YWRtaW46aGVsbG8="), ("x-forwarded-for", "127.1.1.1"))
  ) extends TestRequestHeader


  // -------- mock for auth data source
  trait TestAuthDS extends AuthenticationDataSource {

    lazy val authRequired = true
    lazy val username = "admin"
    lazy val password = "password"
    lazy val realm = "testcompany.com"
    lazy val excluded: List[String] = List("contact.html", "about.html")

    def isExcluded(requestHeader: RequestHeader): Boolean = {
      println(s"URI: ${requestHeader.uri.substring(1)}")
      excluded.contains(requestHeader.uri.substring(1))
    }

    def logFailure(requestHeader: RequestHeader, errMsg: Option[String] = None) = {
      val msg = errMsg.map(e => s"Error: $e").getOrElse("")
      println(s"IP address ${getUserIP(requestHeader)} failed to log in, " + s"requested uri: '${requestHeader.uri}' ${msg}")
    }

    def logSuccess(requestHeader: RequestHeader, user: String) = {
      println(s"User '$user' logged in successfully. IP address ${getUserIP(requestHeader)}, " + s"requested uri: '${requestHeader.uri}'")
    }

    private def getUserIP(request: RequestHeader): String =
      request.headers.get("x-forwarded-for").getOrElse(request.remoteAddress.toString)
  }

  object AuthTest extends HttpBasicAuthenticator with TestAuthDS

  val rh = RequestHeader


  def run(rh: RequestHeader): Int = {
    val f = AuthTest(rh => Future.successful(Results.Ok))(rh)
    val r: Result = Await.result(f, 1 second)
    r.header.status
  }

  "Basic Auth Filter" should {

    "allow valid request" in {
      run(ValidRequestRH()) must beEqualTo(200)
    }

    "allow access to excluded resource" in {
      run(ExcludedResourceRH()) must beEqualTo(200)
    }

    "reject request with invalid credentials" in {
      run(InvalidCredentialsRH()) must beEqualTo(401)
    }

    "reject request without authentication info" in {
      run(AuthNotSetRH()) must beEqualTo(401)
    }

  }

}
