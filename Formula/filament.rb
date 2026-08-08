# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.8.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.8.1/filament-aarch64-apple-darwin.tar.gz"
      sha256 "3d1cdaa9a2d9932d5150f698fa7bb7a47e8816469aa257811584495eaecbe113"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.8.1/filament-x86_64-apple-darwin.tar.gz"
      sha256 "09bbab13b14c8bb30d2706274074e64f1eb1fef5c46bae635bcbc5ad0a1476a6"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.8.1/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "ee5776fa9f7a891fa76ec0b9547e5103f31a7910c548a496a239b5e8b1def944"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
