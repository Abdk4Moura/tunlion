# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.2.1-beta.33"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.33/filament-aarch64-apple-darwin.tar.gz"
      sha256 "657175a7c263e159bdbb4a857be72e128e1158df6d2ada36d468da901fc02ae3"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.33/filament-x86_64-apple-darwin.tar.gz"
      sha256 "a3570a19f13ef0b4f1c67ba3081061e82405c412c42b810aab39f8971fdc32a2"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.33/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "8b79f7ae9ee5a1ee3f891cdd4afa0f449e14f0ec10f3cb96af29237d404aeb5c"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
