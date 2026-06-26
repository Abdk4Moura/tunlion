# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.2.1-beta.21"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.21/filament-aarch64-apple-darwin.tar.gz"
      sha256 "72a2f2847778e213a23fb5388b7ad8423208c52dd9a5e7bd08394259c5c01825"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.21/filament-x86_64-apple-darwin.tar.gz"
      sha256 "14ab801aef19daeaf34499ef848895ac9bf053a1c40565a585d29929f86924fe"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.21/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "2dca9e6216082f5fcf2167a51790096e0b18a3166ed36659518e723037263380"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
