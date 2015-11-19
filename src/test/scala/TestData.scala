import play.api.mvc.{Headers, RequestHeader}

object TestData {

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

}
