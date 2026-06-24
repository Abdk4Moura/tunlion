# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.2.1-beta.15"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.15/filament-aarch64-apple-darwin.tar.gz"
      sha256 "28d05e5531497be8f594f7978edebce767f2132f142f242d5c8e09a3c8165db2"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.15/filament-x86_64-apple-darwin.tar.gz"
      sha256 "1e5c27ad4c2e99391595ca5ee7c4f243f872c55e63e8488c6fbb79f2324334e7"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.15/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "fa0038cab89f7b1dd60e77738d181e3cf08d5f6eb88891e9b8fd52e5ef3aadae"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
