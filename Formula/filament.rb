# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.8.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.8.0/filament-aarch64-apple-darwin.tar.gz"
      sha256 "565f1d959af58671e78c66c2490e434f0b895b3c2255dc64985cdf913c5c4eca"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.8.0/filament-x86_64-apple-darwin.tar.gz"
      sha256 "07547aa5cea7386ffb45e7f885a36deb89ecbd746ecc882d440484b86aa47566"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.8.0/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "a3714b46e9529ad71aaeebee4f930f20161ce19fcc6ca519530623b05610d43e"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
