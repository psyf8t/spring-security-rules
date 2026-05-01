import org.springframework.http.ResponseCookie;
import javax.servlet.http.Cookie;

class T {
    void badResponseCookieNoFlags() {
        // ruleid: spring-responsecookie-not-secure
        ResponseCookie c = ResponseCookie.from("sid", "v").path("/").build();
    }

    void badResponseCookieOnlyHttpOnly() {
        // ruleid: spring-responsecookie-not-secure
        ResponseCookie c = ResponseCookie.from("sid", "v").httpOnly(true).path("/").build();
    }

    void okResponseCookieBoth() {
        // ok: spring-responsecookie-not-secure
        ResponseCookie c = ResponseCookie.from("sid", "v").secure(true).httpOnly(true).path("/").build();
    }

    void okResponseCookieReversed() {
        // ok: spring-responsecookie-not-secure
        ResponseCookie c = ResponseCookie.from("sid", "v").httpOnly(true).secure(true).path("/").build();
    }

    void badServletCookieMissing() {
        // ruleid: spring-cookie-missing-secure-httponly
        Cookie c = new Cookie("sid", "v");
        c.setPath("/");
    }

    void okServletCookieBoth() {
        // ok: spring-cookie-missing-secure-httponly
        Cookie c = new Cookie("sid", "v");
        c.setSecure(true);
        c.setHttpOnly(true);
    }
}
