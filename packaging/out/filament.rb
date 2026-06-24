# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.2.1-beta.14"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.14/filament-aarch64-apple-darwin.tar.gz"
      sha256 "2532a67f2b31615bd5d46a03bed630e35f92ee2a324ce917b10273d281ba0c09"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.14/filament-x86_64-apple-darwin.tar.gz"
      sha256 "86de837ef0836bfe1ed440f87929f47298afff8a6c633737cd32bc0610432bc2"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.14/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "76788b535b97de23531fb98d1b8b464fe19f25fadddeda8fec14a2730c53a9d5"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
