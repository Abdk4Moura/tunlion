# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.2.1-beta.17"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.17/filament-aarch64-apple-darwin.tar.gz"
      sha256 "cb79dbb3b6fd307e657c27274e088432f77995dfe0efd70ee14aff659cb9f6da"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.17/filament-x86_64-apple-darwin.tar.gz"
      sha256 "f910998f713555ceee57d02179749f0700c366035143b0dd3b1c1c77cc637544"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.17/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "286b67eb3b4cc26e62cccebf2c174df7e5593a295f8188b50ba4034f39cedd6a"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
