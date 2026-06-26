# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.2.1-beta.20"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.20/filament-aarch64-apple-darwin.tar.gz"
      sha256 "b2936cd8fe9f6bd35a7804fdb790c554a305e77facaa49c589a69b3ef66d3dca"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.20/filament-x86_64-apple-darwin.tar.gz"
      sha256 "e840651c4eac3a066951701a7e055de624d9892d86e652b4c93d17b69c616354"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.20/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "a3bb162412ea8e88e959fa185aedc2227e1a2495ccbb8ac60526e7bed0bc14b3"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
