# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.5.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.5.0/filament-aarch64-apple-darwin.tar.gz"
      sha256 "67c94127b9be0a0b9209124ddd353434a3d3ec52b2726c40d62123881a102a23"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.5.0/filament-x86_64-apple-darwin.tar.gz"
      sha256 "e8e278780580df7bc00a8b27c25cd4359fc7a831ed844a26c32d8daf32ca8405"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.5.0/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "d213109b67f26a905fc563905f6b494140ed9c87698967b22deeea19c1ddb5bc"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
