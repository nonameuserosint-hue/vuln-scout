function renderGreeting(name) {
  const banner = document.getElementById("greeting");
  banner.innerHTML = name;
}

renderGreeting(new URLSearchParams(window.location.search).get("name") || "guest");
