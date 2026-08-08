# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.8.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.8.2/filament-aarch64-apple-darwin.tar.gz"
      sha256 "d71e8b04738a914a875466d650fa27abed410775d9aec3b6bdb1be978f00cd5d"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.8.2/filament-x86_64-apple-darwin.tar.gz"
      sha256 "b53c122a01c85be9036b3668a7fa4875e8637922e485ba7bbb946fe9b6371341"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.8.2/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "f184bcada572ec741d85bf297f26abd5accce2f5fbc1ae56057d5a3d55d36080"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
