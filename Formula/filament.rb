# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.2.1-beta.16"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.16/filament-aarch64-apple-darwin.tar.gz"
      sha256 "496d3b028ae19e4c35bc5865d65cd62df30bc430ec1a3edac895fce2cd1a5614"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.16/filament-x86_64-apple-darwin.tar.gz"
      sha256 "817fcf4c6706ce01a3e0f167b58462a363b92842fbc9470e22865560a952d6be"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.16/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "7de22349be0146f6fd4cde4ed4d0e7797fb27ed398ce5935f9c0bbc8ed59f76e"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
