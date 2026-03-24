public class UserController {
  public String buildQuery(String email) {
    return "SELECT * FROM users WHERE email = '" + email + "'";
  }
}
