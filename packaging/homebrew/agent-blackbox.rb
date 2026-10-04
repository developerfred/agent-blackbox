# Homebrew formula for agent-blackbox.
# Lives in a tap repository named `homebrew-tap` (github.com/developerfred/homebrew-tap),
# installed with: brew install developerfred/tap/agent-blackbox
# On each release: update `url` to the new tag and `sha256` to the tarball's hash
# (curl -sL <url> | shasum -a 256).
class AgentBlackbox < Formula
  desc "Tamper-evident flight recorder and prompt-injection firewall for AI coding agents"
  homepage "https://github.com/developerfred/agent-blackbox"
  url "https://github.com/developerfred/agent-blackbox/archive/refs/tags/v0.2.0.tar.gz"
  sha256 "REPLACE_WITH_THE_SHA256_OF_THE_RELEASE_TARBALL"
  license "Apache-2.0"

  depends_on "node"

  def install
    libexec.install "dist", "package.json", "README.md", "LICENSE"
    (bin/"blackbox").write_env_script libexec/"dist/bin/blackbox.js",
      PATH: "#{Formula["node"].opt_bin}:$PATH"
  end

  def caveats
    <<~EOS
      To record and protect your Claude Code sessions:
        blackbox install
      To audit your past sessions first (nothing is uploaded):
        blackbox scan
    EOS
  end

  test do
    assert_match "agent-blackbox", shell_output("#{bin}/blackbox help")
  end
end
