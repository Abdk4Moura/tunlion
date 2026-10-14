# Homebrew formula for the tunlion CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
# Placeholder until cli-v0.9.0 is tagged: the zero checksums make any install
# fail closed, and release-followup.sh overwrites this file with the real ones.
class Tunlion < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://tunlion.autumated.com"
  version "0.9.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/tunlion/releases/download/cli-v0.9.0/tunlion-aarch64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    else
      url "https://github.com/Abdk4Moura/tunlion/releases/download/cli-v0.9.0/tunlion-x86_64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/tunlion/releases/download/cli-v0.9.0/tunlion-x86_64-unknown-linux-musl.tar.gz"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  end

  def install
    bin.install "tunlion"
    generate_completions_from_executable(bin/"tunlion", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/tunlion --version")
  end
end
