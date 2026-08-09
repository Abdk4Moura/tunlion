# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.8.5"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.8.5/filament-aarch64-apple-darwin.tar.gz"
      sha256 "37eb6927073e4e27bf664057d30c2564aef8273c6756c6d06885d705554648e4"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.8.5/filament-x86_64-apple-darwin.tar.gz"
      sha256 "8b2e68c49244de33e99b8b36e178eccb79ec8c155ff9a9b2d192c23cf754dea7"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.8.5/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "a8c32f37a0c456ea60be8a313b60e59da5844a818964d4eeb8215728c451dc42"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
