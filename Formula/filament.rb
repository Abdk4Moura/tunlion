# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.4.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.4.1/filament-aarch64-apple-darwin.tar.gz"
      sha256 "10ef97106ba747a70d0aca40349ad3e11d2e0bfed309cc039128713521e8014a"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.4.1/filament-x86_64-apple-darwin.tar.gz"
      sha256 "4a661b168670c8bcb2058914aa00b4e5023a7cd1615c2378255f3669bf9ecd93"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.4.1/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "0d027fcc406bb465ea73bd971fe9cf1ad42e6de0199fb21295e87ee5b61b6371"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
