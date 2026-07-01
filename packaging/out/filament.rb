# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.2.1-beta.28"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.28/filament-aarch64-apple-darwin.tar.gz"
      sha256 "9d29c612952df2e3740e07ca2a657ef97d9e2c0fcfa71f4090e7829e5386e347"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.28/filament-x86_64-apple-darwin.tar.gz"
      sha256 "cc7ff585548eaa4305affd241fe8cdca0e93020d9efa0182a6ccd643357e2f3d"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.28/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "ce11b751fe454851688991f147928c351960ca0c02991cafa1756e38f4c17d39"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
