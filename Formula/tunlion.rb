# Homebrew formula for the tunlion CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Tunlion < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://tunlion.autumated.com"
  version "0.9.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/tunlion/releases/download/cli-v0.9.1/tunlion-aarch64-apple-darwin.tar.gz"
      sha256 "375f059cc82d7e669ec4252a7c9113c83abf37307316e0a30ba9135ef0ddc42d"
    else
      url "https://github.com/Abdk4Moura/tunlion/releases/download/cli-v0.9.1/tunlion-x86_64-apple-darwin.tar.gz"
      sha256 "21307e25f58e5908810ac59057a1fc966e83a95e7b7cf646bb1dec37296e17cc"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/tunlion/releases/download/cli-v0.9.1/tunlion-x86_64-unknown-linux-musl.tar.gz"
    sha256 "d2a7c82902880b0ad3875cb47fd19837960b58681359c21075aaef63e07442b3"
  end

  def install
    bin.install "tunlion"
    # `tl` is a convenience alias; it resolves to the canonical binary, so
    # `tl update` and `tl --version` behave exactly like `tunlion ...`.
    bin.install_symlink "tunlion" => "tl"
    generate_completions_from_executable(bin/"tunlion", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/tunlion --version")
    assert_match version.to_s, shell_output("#{bin}/tl --version")
  end
end
