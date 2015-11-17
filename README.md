HTTP Basic Authentication filter based on the [implementation by Dimitry Kudryavtsev](http://www.mentful.com/2014/06/14/basic-authentication-filter-for-play-framework/).

The original implementation has been modified to allow for different sources of authentication parameters and logging.
Extend AuthenticationDataSource to obtain the authentication information from the required source and mix it with HttpBasicAuthenticator filter.

## Example

**Configuration**
```
auth {
  realm = "www.yourcompany.com"
  username = "admin"
  password = "GcX?&LL77PW~7D;VJ2LXYZ"
  required = true
  excluded = [about.html, contact.html]
}
```

**Global.scala**

```scala
import bline.play.basicauth.{HttpBasicAuthenticator, AuthenticationDataSource}
import play.api.Play._
import play.api.mvc.{WithFilters, RequestHeader}
import collection.JavaConversions._

/**
  * Defines configuration as a source for authentication data
  */
trait ConfigAuthenticationDataSource extends AuthenticationDataSource {

  lazy val auth = current.configuration.getConfig("auth")
  lazy val authRequired = auth.map(_.getBoolean("required").getOrElse(true)).getOrElse(true)
  lazy val username = auth.map(_.getString("username").getOrElse("")).getOrElse("")
  lazy val password = auth.map(_.getString("password").getOrElse("")).getOrElse("")
  lazy val realm = auth.map(_.getString("realm").getOrElse("")).getOrElse("")
  lazy val excluded: List[String] = auth.flatMap(_.getStringList("excluded")).map(_.toList).getOrElse(List[String]())

  def isExcluded(requestHeader: RequestHeader): Boolean =
    excluded.contains(requestHeader.uri.substring(1))

  def logFailure(requestHeader: RequestHeader, errMsg: Option[String] = None) = {
    val msg = errMsg.map(e => s"Error: $e").getOrElse("")
    println(s"IP address ${getUserIP(requestHeader)} failed to log in, " + s"requested uri: '${requestHeader.uri}' ${msg}")
  }

  def logSuccess(requestHeader: RequestHeader, user: String) = {
    println(s"User '$user' logged in successfully. IP address ${getUserIP(requestHeader)}, " + s"requested uri: '${requestHeader.uri}'")
  }

  //This is needed if you are behind a load balancer or a proxy
  private def getUserIP(request: RequestHeader): String =
    request.headers.get("x-forwarded-for").getOrElse(request.remoteAddress.toString)
}

object AuthenticationFilter extends HttpBasicAuthenticator with ConfigAuthenticationDataSource

object Global extends WithFilters(AuthenticationFilter) {
}
```
