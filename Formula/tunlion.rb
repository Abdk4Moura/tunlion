# Homebrew formula for the tunlion CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Tunlion < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://tunlion.autumated.com"
  version "0.9.3"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/tunlion/releases/download/cli-v0.9.3/tunlion-aarch64-apple-darwin.tar.gz"
      sha256 "1db0dc080ae5c557c993d4282a0433fb626b6b99f58bf546b53affe6c526396b"
    else
      url "https://github.com/Abdk4Moura/tunlion/releases/download/cli-v0.9.3/tunlion-x86_64-apple-darwin.tar.gz"
      sha256 "ffd0c094cae0338c7ab443fd5ca77050795ca4ffc49f4bceab4703a71ca7fd40"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/tunlion/releases/download/cli-v0.9.3/tunlion-x86_64-unknown-linux-musl.tar.gz"
    sha256 "123a5c3f5ffab5cf04cca44b1df7ef0698a1463ddba7bffe9846ef927bc2ea8e"
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
