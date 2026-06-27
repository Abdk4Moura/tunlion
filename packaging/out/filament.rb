# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.2.1-beta.22"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.22/filament-aarch64-apple-darwin.tar.gz"
      sha256 "ee86d7ea8e75a716c6d0cb3cb445855afd858092e5db33760f38637755e4c03d"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.22/filament-x86_64-apple-darwin.tar.gz"
      sha256 "2186e470a2740c8c471df084bff0f86858afde26a408209211df7d91b4d6952d"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.22/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "ae24fd39653dbb42ea134363fda371ce618740ad86e7fb00183113df3956b356"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
