import java.io.IOException;

public class App {
  public Process start(String host) throws IOException {
    return new ProcessBuilder("ping", host).start();
  }
}
