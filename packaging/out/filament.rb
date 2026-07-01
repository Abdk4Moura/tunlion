# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.2.1-beta.30"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.30/filament-aarch64-apple-darwin.tar.gz"
      sha256 "5cdcbf4db16ef59c3e3a917fdad156b386937d171d75fe9ba0d645308ef2d0d3"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.30/filament-x86_64-apple-darwin.tar.gz"
      sha256 "bc4a4c8c5a2a602ef11cc0feccc3ee3a0e8234b2fe1609e46fb6f66a428518dc"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.30/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "b6afbb025c80a94fdc338718bee133e4e9fadec4d4d0d994b17288dc74bfa693"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
