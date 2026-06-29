# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.2.1-beta.25"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.25/filament-aarch64-apple-darwin.tar.gz"
      sha256 "a4a0e98f2d4f3168ef4cb5f1345398958e6fb55fdd26efe9d7e07cae96375a5c"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.25/filament-x86_64-apple-darwin.tar.gz"
      sha256 "4c17241a738806bacce6fda18262a8452ee61262c6f2e282930e34c63473af19"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.25/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "336076fe9e98cc028b4bd386b7651b69b8f832287d4d49ebfaa0435ef8e4f107"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
