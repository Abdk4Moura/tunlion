# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.2.1-beta.26"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.26/filament-aarch64-apple-darwin.tar.gz"
      sha256 "ffd13339ec56d890a48d928704cb1ef4e7bdb5eb964ddca9068cda32655f29a8"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.26/filament-x86_64-apple-darwin.tar.gz"
      sha256 "ed4d9e938853abee8fe9f85d39b1da6b5c2d7222a0f9783f09a7aa84a29a33e1"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.26/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "3b8da3037784737c9c5373a9d63a0c531f1add7ff423107f20a94b710e2e012e"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
