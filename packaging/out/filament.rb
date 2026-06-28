# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.2.1-beta.23"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.23/filament-aarch64-apple-darwin.tar.gz"
      sha256 "f85e40c51674cd7bf9b79eb5df8780c31bb78e82ade36d2141841083a0ec556e"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.23/filament-x86_64-apple-darwin.tar.gz"
      sha256 "18bd651e1553bf8c43bec19fdceca30e742798ab084fa8a74398372ba74261f9"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.23/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "0c033a2a2e061c2abd46b5df7059efe53a4abe952b994354b3f85afedcd7ab2c"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
