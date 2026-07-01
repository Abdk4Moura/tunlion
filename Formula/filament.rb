# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.2.1-beta.27"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.27/filament-aarch64-apple-darwin.tar.gz"
      sha256 "4544e6cb998510c8b9fba5247b4dec88e637424f36e6085988ac415fc7fdd270"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.27/filament-x86_64-apple-darwin.tar.gz"
      sha256 "19d8a72e78ea8313f513b82ef812650aeee961a765a3500fc1558639c8a34bee"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.27/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "a24062c8f8c28c05e2705e9b5c3e44c780f8927d6ee5e5d8cc7927493ae0ffc6"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
