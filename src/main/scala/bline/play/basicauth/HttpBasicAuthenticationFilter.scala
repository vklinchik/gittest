package bline.play.basicauth


import play.api.mvc.{Filter, RequestHeader, Result}
import play.api.http.HeaderNames.{AUTHORIZATION, WWW_AUTHENTICATE}
import play.api.mvc.Results.Unauthorized
import scala.concurrent.Future
import scala.util.Try


trait Authenticator {

  def realm: String

  def authorized(user: String, pass: String, resource: String): Boolean

  /**
    * Called by HttpBasicAuthenticationFilter on failure
    * @param ip Client IP address
    * @param uri Requested Resource
    * @param reason Reason for failure
    */
  def failure(ip: String, uri: String, reason: String): Unit = {
  }

  /**
    * Called by HttpBasicAuthenticationFilter on success
    * @param ip Client IP address
    * @param uri Requested Resource
    * @param user User name
    */
  def success(ip: String, uri: String, user: String) = {
  }
}


/**
  */
trait HttpBasicAuthenticationFilter extends Filter { this: Authenticator =>

  private[this] lazy val UnauthorizedResult = Future.successful(
    Unauthorized.withHeaders( WWW_AUTHENTICATE -> s"""Basic realm="${realm}"""")
  )
  private[this] val BasicString = "BASIC "

  /**
    * Extract authentication string
    * @param auth
    * @return
    */
  private def extract(auth: String): Option[String] = {
    Try {
      val s = auth.substring(0, BasicString.length())
      if (s.toUpperCase != BasicString) throw new IllegalArgumentException("Invalid authentication parameter")
      auth.replaceFirst(s, "")
    }.toOption
  }

  /**
    * Decode authentication string
    * @param auth
    * @return user name and password
    */
  private def decode(auth: String): Option[(String, String)] = {
    import java.util.Base64.getDecoder

    extract(auth).flatMap { s =>
      val decoded = new String(getDecoder.decode(s), "UTF-8")
      val usernamePassword = decoded.split(":")
      Try(Some((usernamePassword(0), usernamePassword.splitAt(1)._2.mkString))).getOrElse(None)
    }
  }

  /**
    * Extract IP adddress from the request header
    * @param request Request header
    * @return IP address
    */
  private def getIp(request: RequestHeader): String =
    request.headers.get("x-forwarded-for").getOrElse(request.remoteAddress.toString)



  def apply(nextFilter: (RequestHeader) => Future[Result])(rh: RequestHeader): Future[Result] = {

    rh.headers.get(AUTHORIZATION).map { basicAuth =>
      decode(basicAuth) match {
        case Some((user, pass)) if(authorized(user, pass, rh.uri.substring(1))) =>
          success(getIp(rh), rh.uri, user)
          nextFilter(rh)
        case _ =>
          failure(getIp(rh), rh.uri, "Invalid credentials or authorization information.")
          UnauthorizedResult
      }
    } getOrElse {
      failure(getIp(rh), rh.uri, "Authorization header is not set.")
      UnauthorizedResult
    }

  }


}


/**
  * DefaultAuthenticator - configuration as a source for authentication data
  * Sample configuration:
  * # HTTP Basic Authentication configuration
  * auth.realm = "www.yourcompany.com"
  * auth.credentials = [
  *   { user: "admin", password: "password"},
  *   { user: "john", password: "password2"}
  * ]
  * auth.required = true
  * auth.excluded = [about.html, contact.html]
  *
  */
trait DefaultAuthenticator extends Authenticator {

  import scala.collection.JavaConversions._
  import play.api.Play.current
  import play.api.Logger

  lazy val c = current.configuration
  lazy val authRequired = c.getBoolean("auth.required").getOrElse(true)
  lazy val realm = c.getString("auth.realm").getOrElse("")
  lazy val excluded: List[String] = c.getStringList("auth.excluded").map(_.toList).getOrElse(List())

  lazy val credentials = c.getConfigList("auth.credentials").map(_.toList).getOrElse(List())
  lazy val users = credentials.map(o => (o.getString("user").getOrElse(""), o.getString("password").getOrElse(""))).toMap

  def authorized(user: String, pass: String, resource: String) = {
    if( authRequired ) {
      if (excluded.contains(resource)) true
      else users.get(user).map(_ == pass).getOrElse(false)
    }
    else true
  }

  override def failure(ip: String, uri: String, reason: String) = {
    Logger.error(s"IP address ${ip} failed to log in, " + s"requested uri: '${uri}' Error: ${reason}")
  }

  override def success(ip: String, uri: String, user: String) = {
    Logger.debug(s"User '$user' logged in successfully. IP address ${ip}, " + s"requested uri: '${uri}'")
  }
}


/**
  * Default authentication filter
  * Usage:
  * object Global extends WithFilters(DefaultAuthenticationFilter)
  */
object DefaultAuthenticationFilter extends HttpBasicAuthenticationFilter with DefaultAuthenticator


