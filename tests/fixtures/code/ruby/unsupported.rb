def load_user(email)
  sql = "SELECT * FROM users WHERE email = '#{email}'"
  DB.execute(sql)
end
