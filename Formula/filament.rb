# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.2.1-beta.18"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.18/filament-aarch64-apple-darwin.tar.gz"
      sha256 "951e54bd856f204fa3032965042666e9eb7e7b700d1a9f1603d8f1694fef91d9"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.18/filament-x86_64-apple-darwin.tar.gz"
      sha256 "e6221617bf5cb2db36dae0740e6c175563436e6f727ffda84bc6a342cb170df3"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.18/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "9fb9d684c283dde5acbb0578a3334ffe36a44b50c42e78433ca89812eff1f1ff"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
