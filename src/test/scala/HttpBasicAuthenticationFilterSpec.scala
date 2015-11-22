

import mindriot.play.basicauth.{HttpBasicAuthenticationFilter, Authenticator}
import org.specs2.mutable._
import play.api.mvc.{Result, Results, RequestHeader}

import scala.concurrent.{Await, Future}
import scala.concurrent.duration._

class HttpBasicAuthenticationFilterSpec extends Specification {

  import TestData._

  trait TestAuthenticator extends Authenticator {

    val realm = "testcompany.com"
    val excluded: List[String] = List("contact.html", "about.html")
    val users = Map("admin" -> "password", "john" -> "password2")

    def authorized(user: String, pass: String, resource: String) = {
      if(excluded.contains(resource)) true
      else users.get(user).map(_ == pass).getOrElse(false)
    }

    override def failure(ip: String, uri: String, reason: String) = {
      println(s"IP address ${ip} failed to log in, " + s"requested uri: '${uri}' Error: ${reason}")
    }

    override def success(ip: String, uri: String, user: String) = {
      println(s"User '$user' logged in successfully. IP address ${ip}, " + s"requested uri: '${uri}'")
    }


  }

  object AuthTest extends HttpBasicAuthenticationFilter with TestAuthenticator

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
