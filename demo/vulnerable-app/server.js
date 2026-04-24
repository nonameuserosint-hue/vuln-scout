const express = require("express");

const app = express();
app.use(express.urlencoded({ extended: false }));

app.get("/login/callback", (req, res) => {
  res.redirect(req.query.next);
});

app.listen(3000);
