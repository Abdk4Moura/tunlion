# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.2.1-beta.24"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.24/filament-aarch64-apple-darwin.tar.gz"
      sha256 "196687c7845ed2bbf15998c0a2c1a414dfae695d823ced26f595cd774d71d145"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.24/filament-x86_64-apple-darwin.tar.gz"
      sha256 "1e7a568fdd3eeddd1ce599c75d72a7a07241724fc53e4c282806bd59db08caa4"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.24/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "5dc82f322160aff1e814038fdd13124562e58d1a8e94b528996fbc85bdc74bf6"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
