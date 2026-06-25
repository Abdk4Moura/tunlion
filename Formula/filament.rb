# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.2.1-beta.19"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.19/filament-aarch64-apple-darwin.tar.gz"
      sha256 "3ce091dccb5ebb15fceace119625375e6c99b02dff403e3ab7a09beeb53cf48c"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.19/filament-x86_64-apple-darwin.tar.gz"
      sha256 "001c1f4199dac5c74d6650e1896ee77482ed56d6301335e76cb1d88b496d07f2"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.19/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "3c0dbdde55b323472459b371f7bf501846ba8342c513db234619e457f33bdd8d"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
