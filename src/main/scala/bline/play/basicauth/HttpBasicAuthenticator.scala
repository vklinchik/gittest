package bline.play.basicauth

import play.api.mvc._
import scala.concurrent.Future

import scala.util.Try


trait AuthenticationDataSource {

  def authRequired: Boolean
  def username: String
  def password: String
  def realm: String

  def isExcluded(rh: RequestHeader): Boolean
  def logFailure(rh: RequestHeader, errMsg: Option[String] = None)
  def logSuccess(rh: RequestHeader, user: String)
}


/**
  * HTTP Basic Authenticator filter based on the original implementation by Dimitry Kudryavtsev
  * Modified to allow different sources of auth configuration parameters and logging.
  * Extend AuthenticationDataSource to obtain the authentication information
  * from the required source and mix it with HttpBasicAuthenticator filter
  *
  * @see See original implementation: http://www.mentful.com/2014/06/14/basic-authentication-filter-for-play-framework/
  * @author vklinchik
  */
trait HttpBasicAuthenticator extends Filter { this: AuthenticationDataSource =>

  import java.util.Base64.getDecoder

  private lazy val unauthResult = Results.Unauthorized.withHeaders(("WWW-Authenticate", s"""Basic realm="${realm}""""))
  private val BasicStr = "basic "


  /**
    * Extract authentication string
    * @param auth
    * @return
    */
  private def extract(auth: String): Option[String] =
    Try {
      val s = auth.substring(0, BasicStr.length())
      if(s.toLowerCase != BasicStr) throw new IllegalArgumentException("Invalid authentication parameter")
      auth.replaceFirst(s, "")
    }.toOption

  /**
    * Decode authentication string
    * @param auth
    * @return
    */
  private def decode(auth: String): Option[(String, String)] =
    extract(auth).flatMap { s =>
      val decoded = new String(getDecoder.decode(s), "UTF-8")
      val usernamePassword = decoded.split(":")
      Try(Some((usernamePassword(0), usernamePassword.splitAt(1)._2.mkString))).getOrElse(None)
    }



  def apply(nextFilter: (RequestHeader) => Future[Result])(rh: RequestHeader): Future[Result] = {

    if (authRequired && (username.isEmpty || password.isEmpty)) {
      logFailure(rh, Some("Authorization credentials are not configured."))
      Future.successful(unauthResult)
    }
    else if (!authRequired || isExcluded(rh)) {
      nextFilter(rh)
    }
    else {
      rh.headers.get("authorization").map { basicAuth =>
        decode(basicAuth) match {
          case Some((user, pass)) if (username == user && password == pass) =>
            logSuccess(rh, user)
            nextFilter(rh)
          case _ =>
            logFailure(rh, Some("Invalid authorization information."))
            Future.successful(unauthResult)
        }
      } getOrElse {
        logFailure(rh, Some("Authorization header is not set."))
        Future.successful(unauthResult)
      }
    }

  }


}
