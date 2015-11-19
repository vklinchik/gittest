HTTP Basic Authentication Filter for [playframework](http://www.playframework.com) enforces access control to web resources.

This implementation allows for different sources of authentication data. 
Extend Authenticator trait to obtain the authentication information from the specific source and implement custom authorization function;
and mix in with HttpBasicAuthenticationFilter.


**Example**

```scala
trait SampleAuthenticator extends Authenticator {

  val authRequired = true
  val realm = "XYZ"
  val excluded = List("about.html", "contact.html")

  val users = Map("admin" -> "password")
  
  def authorized(user: String, pass: String, resource: String) = {
    if( authRequired ) {
      if (excluded.contains(resource)) true
      else users.get(user).map(_ == pass).getOrElse(false)
    }
    else true
  }

  override def failure(ip: String, uri: String, reason: String) = {
    println(s"IP address ${ip} failed to log in, " + s"requested uri: '${uri}' Error: ${reason}")
  }

  override def success(ip: String, uri: String, user: String) = {
    println(s"User '$user' logged in successfully. IP address ${ip}, " + s"requested uri: '${uri}'")
  }
}
```




## DefaultAuthenticationFilter

DefaultAuthenticationFilter is provided as part of the package and uses configuration as a source.

**Sample Configuration**
```
# HTTP Basic Authentication configuration
auth.realm = "www.yourcompany.com"
auth.credentials = [
    { user: "admin", password: "password"},
    { user: "john", password: "password2"}
  ]
auth.required = true
auth.excluded = [about.html, contact.html]
```

To use DefaultAuthenticationFilter extend WithFilters trait on your Global object and 
supply DefaultAuthenticationFilter as a parameter.


**Global.scala**

```scala
import bline.play.basicauth.DefaultAuthenticationFilter

object Global extends WithFilters(DefaultAuthenticationFilter) {
}
```
